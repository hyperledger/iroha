use crate::{
    HedgedChaCha20Rng, HedgedRngSeed, RngError, deterministic_chacha20_rng,
    hedged_chacha20_rng_from_rng,
};
use core::fmt;
use pqcrypto_mldsa::{mldsa44, mldsa65, mldsa87};
use pqcrypto_traits::{
    Error as PqError,
    sign::{
        DetachedSignature as PrimitiveDetachedSignature, PublicKey as PrimitivePublicKey,
        VerificationError,
    },
};
use rand_core::{RngCore, TryCryptoRng};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};
#[path = "mldsa_backend.rs"]
mod backend;
#[path = "mldsa_primitives.rs"]
mod mldsa_primitives;
#[path = "mldsa_sign.rs"]
mod signer;
#[path = "mldsa_verify.rs"]
mod verifier;
pub use signer::sign_mldsa65_detached;
pub use verifier::verify_mldsa65_detached;
/// Maximum context length accepted by FIPS 204 ML-DSA signing and verification.
pub const ML_DSA_CONTEXT_MAX_LEN: usize = 255;
/// Supported ML-DSA parameter sets.
#[derive(Clone, Copy, Debug)]
pub enum MlDsaSuite {
    /// ML-DSA-44.
    MlDsa44,
    /// ML-DSA-65.
    MlDsa65,
    /// ML-DSA-87.
    MlDsa87,
}
impl MlDsaSuite {
    /// Return the numeric identifier used on the FFI surface.
    #[must_use]
    pub const fn suite_id(self) -> u8 {
        match self {
            MlDsaSuite::MlDsa44 => 0,
            MlDsaSuite::MlDsa65 => 1,
            MlDsaSuite::MlDsa87 => 2,
        }
    }
    /// Parse an [`MlDsaSuite`] from its numeric identifier.
    #[must_use]
    pub const fn from_suite_id(id: u8) -> Option<Self> {
        match id {
            0 => Some(MlDsaSuite::MlDsa44),
            1 => Some(MlDsaSuite::MlDsa65),
            2 => Some(MlDsaSuite::MlDsa87),
            _ => None,
        }
    }
    /// Return the public key length in bytes for this suite.
    #[must_use]
    pub fn public_key_len(self) -> usize {
        match self {
            MlDsaSuite::MlDsa44 => mldsa44::public_key_bytes(),
            MlDsaSuite::MlDsa65 => mldsa65::public_key_bytes(),
            MlDsaSuite::MlDsa87 => mldsa87::public_key_bytes(),
        }
    }
    /// Return the secret key length in bytes for this suite.
    #[must_use]
    pub fn secret_key_len(self) -> usize {
        match self {
            MlDsaSuite::MlDsa44 => mldsa44::secret_key_bytes(),
            MlDsaSuite::MlDsa65 => mldsa65::secret_key_bytes(),
            MlDsaSuite::MlDsa87 => mldsa87::secret_key_bytes(),
        }
    }
    /// Return the detached signature length in bytes for this suite.
    #[must_use]
    pub fn signature_len(self) -> usize {
        match self {
            MlDsaSuite::MlDsa44 => mldsa44::signature_bytes(),
            MlDsaSuite::MlDsa65 => mldsa65::signature_bytes(),
            MlDsaSuite::MlDsa87 => mldsa87::signature_bytes(),
        }
    }
    /// Validate a public key encoding for this suite.
    ///
    /// # Errors
    /// Returns an error when the byte string has the wrong encoded length or
    /// contains inert all-zero key material.
    pub fn validate_public_key(self, bytes: &[u8]) -> Result<(), MlDsaError> {
        validate_mldsa_public_key_len(self, bytes)?;
        validate_mldsa_material_not_all_zero(self, self.public_key_kind(), bytes)
    }
    /// Validate a secret key encoding for this suite.
    ///
    /// # Errors
    /// Returns an error when the byte string has the wrong encoded length or
    /// internally inconsistent public material.
    pub fn validate_secret_key(self, bytes: &[u8]) -> Result<(), MlDsaError> {
        validate_mldsa_secret_key_len(self, bytes)?;
        validate_mldsa_material_not_all_zero(self, self.secret_key_kind(), bytes)?;
        backend::validate_secret_key(self, bytes)
    }
    /// Reconstruct the public key committed by a secret key.
    ///
    /// # Errors
    /// Returns an error when the secret key is malformed or internally inconsistent.
    pub fn public_key_from_secret_key(self, bytes: &[u8]) -> Result<Vec<u8>, MlDsaError> {
        validate_mldsa_secret_key_len(self, bytes)?;
        validate_mldsa_material_not_all_zero(self, self.secret_key_kind(), bytes)?;
        backend::public_key_from_secret_key(self, bytes)
    }
    /// Validate a detached signature encoding for this suite.
    ///
    /// # Errors
    /// Returns an error when the byte string has the wrong encoded length or
    /// contains inert all-zero signature material.
    pub fn validate_signature(self, bytes: &[u8]) -> Result<(), MlDsaError> {
        validate_mldsa_signature_len(self, bytes)?;
        validate_mldsa_material_not_all_zero(self, self.signature_kind(), bytes)
    }
    const fn public_key_kind(self) -> &'static str {
        match self {
            MlDsaSuite::MlDsa44 => "ML-DSA-44 public key",
            MlDsaSuite::MlDsa65 => "ML-DSA-65 public key",
            MlDsaSuite::MlDsa87 => "ML-DSA-87 public key",
        }
    }
    const fn secret_key_kind(self) -> &'static str {
        match self {
            MlDsaSuite::MlDsa44 => "ML-DSA-44 secret key",
            MlDsaSuite::MlDsa65 => "ML-DSA-65 secret key",
            MlDsaSuite::MlDsa87 => "ML-DSA-87 secret key",
        }
    }
    const fn signature_kind(self) -> &'static str {
        match self {
            MlDsaSuite::MlDsa44 => "ML-DSA-44 signature",
            MlDsaSuite::MlDsa65 => "ML-DSA-65 signature",
            MlDsaSuite::MlDsa87 => "ML-DSA-87 signature",
        }
    }
    const fn generated_keypair_kind(self) -> &'static str {
        match self {
            MlDsaSuite::MlDsa44 => "ML-DSA-44 generated key pair",
            MlDsaSuite::MlDsa65 => "ML-DSA-65 generated key pair",
            MlDsaSuite::MlDsa87 => "ML-DSA-87 generated key pair",
        }
    }
}
/// ML-DSA keypair.
pub struct MlDsaKeyPair {
    /// Public key bytes.
    pub public_key: Vec<u8>,
    /// Secret key bytes (zeroized on drop).
    pub secret_key: Zeroizing<Vec<u8>>,
}
impl fmt::Debug for MlDsaKeyPair {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MlDsaKeyPair")
            .field("public_key_len", &self.public_key.len())
            .field("secret_key", &"[REDACTED]")
            .finish()
    }
}
impl MlDsaKeyPair {
    /// Borrow the public key bytes.
    #[must_use]
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }
    /// Borrow the secret key bytes.
    #[must_use]
    pub fn secret_key(&self) -> &[u8] {
        &self.secret_key
    }
}
/// Detached ML-DSA signature.
#[derive(Clone)]
pub struct MlDsaSignature {
    bytes: Vec<u8>,
}
impl fmt::Debug for MlDsaSignature {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MlDsaSignature")
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}
impl MlDsaSignature {
    fn try_new(suite: MlDsaSuite, bytes: Vec<u8>) -> Result<Self, MlDsaError> {
        suite.validate_signature(&bytes)?;
        Ok(Self { bytes })
    }
    /// Access raw signature bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Transfer ownership of the raw signature bytes to the caller.
    ///
    /// The returned allocation is no longer guarded by [`MlDsaSignature`]'s
    /// drop-time scrubbing, so callers should use this only when the signature
    /// must outlive the wrapper (for example, in a serialized protocol object).
    #[must_use]
    pub fn into_bytes(mut self) -> Vec<u8> {
        core::mem::take(&mut self.bytes)
    }

    fn zeroize_sensitive_fields(&mut self) {
        self.bytes.zeroize();
        core::hint::black_box(&self.bytes);
    }
}
impl Drop for MlDsaSignature {
    fn drop(&mut self) {
        self.zeroize_sensitive_fields();
    }
}
/// Error raised by ML-DSA helpers.
#[derive(Clone, Debug, Error)]
pub enum MlDsaError {
    /// Encoding length mismatch.
    #[error(transparent)]
    BadEncoding(Box<MlDsaEncodingError>),
    /// Signature verification failed.
    #[error("signature verification failed: {0}")]
    VerificationFailed(VerificationError),
    /// Context exceeded the FIPS 204 one-byte context length field.
    #[error("ML-DSA context length must be at most 255 bytes, found {len}")]
    ContextTooLong {
        /// Actual context length in bytes.
        len: usize,
    },
    /// Secret key fields are length-valid but internally inconsistent.
    #[error("{suite:?} secret key is internally inconsistent: {kind}")]
    SecretKeyMismatch {
        /// Suite identifier.
        suite: MlDsaSuite,
        /// Identifier of the malformed secret-key component.
        kind: &'static str,
    },
    /// Encoded material is length-valid but inert.
    #[error("{suite:?} {kind} must not be all zero")]
    InertKeyMaterial {
        /// Suite identifier.
        suite: MlDsaSuite,
        /// Identifier of the inert material.
        kind: &'static str,
    },
    /// Hedged RNG seed construction failed.
    #[error(transparent)]
    Rng(#[from] RngError),
}
impl MlDsaError {
    fn bad_encoding(kind: &'static str, err: PqError) -> Self {
        MlDsaError::BadEncoding(Box::new(MlDsaEncodingError { kind, source: err }))
    }
}
fn validate_mldsa_public_key_len(suite: MlDsaSuite, bytes: &[u8]) -> Result<(), MlDsaError> {
    validate_mldsa_len(suite.public_key_kind(), bytes.len(), suite.public_key_len())
}
fn validate_mldsa_secret_key_len(suite: MlDsaSuite, bytes: &[u8]) -> Result<(), MlDsaError> {
    validate_mldsa_len(suite.secret_key_kind(), bytes.len(), suite.secret_key_len())
}
fn validate_mldsa_signature_len(suite: MlDsaSuite, bytes: &[u8]) -> Result<(), MlDsaError> {
    validate_mldsa_len(suite.signature_kind(), bytes.len(), suite.signature_len())
}
fn validate_mldsa_len(
    kind: &'static str,
    actual: usize,
    expected: usize,
) -> Result<(), MlDsaError> {
    if actual == expected {
        Ok(())
    } else {
        Err(MlDsaError::bad_encoding(
            kind,
            PqError::BadLength {
                name: kind,
                actual,
                expected,
            },
        ))
    }
}
fn validate_mldsa_material_not_all_zero(
    suite: MlDsaSuite,
    kind: &'static str,
    bytes: &[u8],
) -> Result<(), MlDsaError> {
    if bytes.iter().all(|&byte| byte == 0) {
        return Err(MlDsaError::InertKeyMaterial { suite, kind });
    }
    Ok(())
}
fn validate_mldsa_seed_material_not_all_zero(
    suite: MlDsaSuite,
    seed: &HedgedRngSeed,
) -> Result<(), MlDsaError> {
    if seed.is_all_zero() {
        return Err(MlDsaError::InertKeyMaterial {
            suite,
            kind: "ML-DSA seed material",
        });
    }
    Ok(())
}
#[derive(Clone, Copy, Debug, Error)]
#[error("invalid {kind} encoding: {source}")]
pub struct MlDsaEncodingError {
    /// Field identifier.
    kind: &'static str,
    /// Underlying `PQClean` error.
    #[source]
    source: PqError,
}
/// Generate an ML-DSA keypair.
///
/// # Errors
///
/// Returns an error when generated material fails strict FIPS 204 encoding and
/// consistency validation.
pub fn generate_mldsa_keypair(
    suite: MlDsaSuite,
    rng: &mut HedgedChaCha20Rng,
) -> Result<MlDsaKeyPair, MlDsaError> {
    let mut coins = Zeroizing::new([0u8; 32]);
    rng.fill_bytes(coins.as_mut());
    generate_mldsa_keypair_from_fips_seed(suite, &coins)
}
/// Deterministically generate an ML-DSA keypair from the 32-byte seed input defined by FIPS 204.
///
/// This is the lowest-level deterministic key-generation entry point. Callers that start with
/// arbitrary-length secret material should first run a domain-separated KDF and zeroize the derived
/// seed after this function returns.
///
/// # Errors
/// Returns an error when `seed` is all zero, or when generated material fails
/// canonical key validation.
pub fn generate_mldsa_keypair_from_fips_seed(
    suite: MlDsaSuite,
    seed: &[u8; 32],
) -> Result<MlDsaKeyPair, MlDsaError> {
    validate_mldsa_material_not_all_zero(suite, "ML-DSA keypair seed", seed)?;
    let keypair = backend::generate_keypair(suite, seed)?;
    validate_generated_mldsa_keypair(suite, &keypair)?;
    Ok(keypair)
}
fn validate_generated_mldsa_keypair(
    suite: MlDsaSuite,
    keypair: &MlDsaKeyPair,
) -> Result<(), MlDsaError> {
    suite.validate_public_key(keypair.public_key())?;
    let reconstructed = suite.public_key_from_secret_key(keypair.secret_key())?;
    if reconstructed != keypair.public_key() {
        return Err(MlDsaError::SecretKeyMismatch {
            suite,
            kind: suite.generated_keypair_kind(),
        });
    }
    Ok(())
}
/// Generate an ML-DSA keypair using a seed plus live OS entropy when available.
///
/// # Errors
/// Returns [`MlDsaError::Rng`] when the initial OS seed draw fails.
pub fn generate_mldsa_keypair_from_os(suite: MlDsaSuite) -> Result<MlDsaKeyPair, MlDsaError> {
    let mut rng = rand::rngs::OsRng;
    generate_mldsa_keypair_from_rng(suite, &mut rng)
}
/// Generate an ML-DSA keypair using caller-supplied seed entropy plus live OS
/// entropy when available.
///
/// # Errors
/// Returns [`MlDsaError::Rng`] when the required seed draw fails, or a backend
/// error when generated material fails validation.
pub fn generate_mldsa_keypair_from_rng<R: TryCryptoRng + ?Sized>(
    suite: MlDsaSuite,
    rng: &mut R,
) -> Result<MlDsaKeyPair, MlDsaError> {
    let mut rng = hedged_chacha20_rng_from_rng(b"soranet-pq:mldsa:keypair", rng)?;
    generate_mldsa_keypair(suite, &mut rng)
}
/// Deterministically generate an ML-DSA keypair from explicit seed material.
///
/// # Errors
/// Returns an error when seed material is all zero, or when generated material
/// fails backend validation.
pub fn generate_mldsa_keypair_from_seed(
    suite: MlDsaSuite,
    seed: HedgedRngSeed,
    personalization: &[u8],
) -> Result<MlDsaKeyPair, MlDsaError> {
    validate_mldsa_seed_material_not_all_zero(suite, &seed)?;
    let mut rng = deterministic_chacha20_rng(seed, personalization);
    generate_mldsa_keypair(suite, &mut rng)
}
/// Create a detached signature over `message` using the provided secret key.
///
/// # Errors
/// Returns an error when the secret key or signature encoding is invalid.
pub fn sign_mldsa(
    suite: MlDsaSuite,
    secret_key: &[u8],
    context: &[u8],
    message: &[u8],
    rng: &mut HedgedChaCha20Rng,
) -> Result<MlDsaSignature, MlDsaError> {
    if context.len() > ML_DSA_CONTEXT_MAX_LEN {
        return Err(MlDsaError::ContextTooLong { len: context.len() });
    }
    suite.validate_secret_key(secret_key)?;
    let mut coins = Zeroizing::new([0u8; 32]);
    rng.fill_bytes(coins.as_mut());
    sign_mldsa_from_coins(suite, secret_key, context, message, &coins)
}
fn sign_mldsa_from_coins(
    suite: MlDsaSuite,
    secret_key: &[u8],
    context: &[u8],
    message: &[u8],
    coins: &[u8; 32],
) -> Result<MlDsaSignature, MlDsaError> {
    validate_mldsa_material_not_all_zero(suite, "ML-DSA signing coins", coins)?;
    let signature = backend::sign(suite, secret_key, context, message, coins)?;
    MlDsaSignature::try_new(suite, signature)
}
/// Sign using fresh OS seed material plus live OS entropy when available.
///
/// # Errors
/// Returns [`MlDsaError::Rng`] when the initial OS seed draw fails, or a backend
/// error when the secret-key encoding is invalid.
pub fn sign_mldsa_from_os(
    suite: MlDsaSuite,
    secret_key: &[u8],
    context: &[u8],
    message: &[u8],
) -> Result<MlDsaSignature, MlDsaError> {
    let mut rng = rand::rngs::OsRng;
    sign_mldsa_from_rng(suite, secret_key, context, message, &mut rng)
}
/// Sign using caller-supplied seed entropy plus live OS entropy when available.
///
/// # Errors
/// Returns [`MlDsaError::Rng`] when the required seed draw fails, or a backend
/// error when the secret-key encoding is invalid.
pub fn sign_mldsa_from_rng<R: TryCryptoRng + ?Sized>(
    suite: MlDsaSuite,
    secret_key: &[u8],
    context: &[u8],
    message: &[u8],
    rng: &mut R,
) -> Result<MlDsaSignature, MlDsaError> {
    if context.len() > ML_DSA_CONTEXT_MAX_LEN {
        return Err(MlDsaError::ContextTooLong { len: context.len() });
    }
    suite.validate_secret_key(secret_key)?;
    let mut rng = hedged_chacha20_rng_from_rng(b"soranet-pq:mldsa:sign", rng)?;
    sign_mldsa(suite, secret_key, context, message, &mut rng)
}
/// Verify a detached signature.
///
/// # Errors
/// Returns an error when the public key or signature encoding is invalid or verification fails.
pub fn verify_mldsa(
    suite: MlDsaSuite,
    public_key: &[u8],
    context: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), MlDsaError> {
    if context.len() > ML_DSA_CONTEXT_MAX_LEN {
        return Err(MlDsaError::ContextTooLong { len: context.len() });
    }
    suite.validate_public_key(public_key)?;
    suite.validate_signature(signature)?;
    match suite {
        MlDsaSuite::MlDsa44 => {
            let pk = mldsa44::PublicKey::from_bytes(public_key)
                .map_err(|err| MlDsaError::bad_encoding("ML-DSA-44 public key", err))?;
            let sig = mldsa44::DetachedSignature::from_bytes(signature)
                .map_err(|err| MlDsaError::bad_encoding("ML-DSA-44 signature", err))?;
            verifier::verify44_ctx(&sig, message, context, &pk)
                .map_err(MlDsaError::VerificationFailed)
        }
        MlDsaSuite::MlDsa65 => {
            let pk = mldsa65::PublicKey::from_bytes(public_key)
                .map_err(|err| MlDsaError::bad_encoding("ML-DSA-65 public key", err))?;
            let sig = mldsa65::DetachedSignature::from_bytes(signature)
                .map_err(|err| MlDsaError::bad_encoding("ML-DSA-65 signature", err))?;
            verifier::verify65_ctx(&sig, message, context, &pk)
                .map_err(MlDsaError::VerificationFailed)
        }
        MlDsaSuite::MlDsa87 => {
            let pk = mldsa87::PublicKey::from_bytes(public_key)
                .map_err(|err| MlDsaError::bad_encoding("ML-DSA-87 public key", err))?;
            let sig = mldsa87::DetachedSignature::from_bytes(signature)
                .map_err(|err| MlDsaError::bad_encoding("ML-DSA-87 signature", err))?;
            verifier::verify87_ctx(&sig, message, context, &pk)
                .map_err(MlDsaError::VerificationFailed)
        }
    }
}
/// Validate the encoding of an ML-DSA public key.
///
/// # Errors
/// Returns an error when the public-key byte string has the wrong encoded length.
pub fn validate_mldsa_public_key(suite: MlDsaSuite, bytes: &[u8]) -> Result<(), MlDsaError> {
    suite.validate_public_key(bytes)
}
/// Validate the encoding of an ML-DSA secret key.
///
/// # Errors
/// Returns an error when the secret-key byte string has the wrong encoded
/// length or internally inconsistent public material.
pub fn validate_mldsa_secret_key(suite: MlDsaSuite, bytes: &[u8]) -> Result<(), MlDsaError> {
    suite.validate_secret_key(bytes)
}
/// Reconstruct the public key committed by an ML-DSA secret key.
///
/// # Errors
/// Returns an error when the secret key is malformed or internally inconsistent.
pub fn mldsa_public_key_from_secret_key(
    suite: MlDsaSuite,
    bytes: &[u8],
) -> Result<Vec<u8>, MlDsaError> {
    suite.public_key_from_secret_key(bytes)
}
/// Validate the encoding of an ML-DSA detached signature.
///
/// # Errors
/// Returns an error when the signature byte string has the wrong encoded length.
pub fn validate_mldsa_signature(suite: MlDsaSuite, bytes: &[u8]) -> Result<(), MlDsaError> {
    suite.validate_signature(bytes)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{deterministic_chacha20_rng, hedged_chacha20_rng};
    use rand_core::{TryCryptoRng, TryRngCore};
    const ML_DSA_SECRET_TR_OFFSET: usize = 64;
    #[derive(Debug)]
    struct FailingPqSeedRng;
    #[derive(Debug)]
    struct FailingPqSeedRngError;
    impl core::fmt::Display for FailingPqSeedRngError {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str("failing ML-DSA seed RNG")
        }
    }
    impl std::error::Error for FailingPqSeedRngError {}
    impl TryRngCore for FailingPqSeedRng {
        type Error = FailingPqSeedRngError;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Err(FailingPqSeedRngError)
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Err(FailingPqSeedRngError)
        }
        fn try_fill_bytes(&mut self, _dst: &mut [u8]) -> Result<(), Self::Error> {
            Err(FailingPqSeedRngError)
        }
    }
    impl TryCryptoRng for FailingPqSeedRng {}
    struct FixedPqSeedRng {
        seed: [u8; 32],
    }
    impl TryRngCore for FixedPqSeedRng {
        type Error = core::convert::Infallible;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(u32::from_le_bytes(self.seed[..4].try_into().unwrap()))
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(u64::from_le_bytes(self.seed[..8].try_into().unwrap()))
        }
        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            for (index, byte) in dst.iter_mut().enumerate() {
                *byte = self.seed[index % self.seed.len()];
            }
            Ok(())
        }
    }
    impl TryCryptoRng for FixedPqSeedRng {}
    fn seeded_keypair(suite: MlDsaSuite, seed: u8, personalization: &'static [u8]) -> MlDsaKeyPair {
        generate_mldsa_keypair_from_seed(
            suite,
            HedgedRngSeed::from_entropy([seed; 32]),
            personalization,
        )
        .expect("seeded keypair generation should succeed")
    }
    fn assert_secret_key_mismatch(err: MlDsaError) {
        match err {
            MlDsaError::SecretKeyMismatch { .. } => {}
            other => panic!("expected secret-key mismatch, got {other:?}"),
        }
    }
    fn assert_inert_key_material(err: MlDsaError, suite: MlDsaSuite, expected_kind_fragment: &str) {
        match err {
            MlDsaError::InertKeyMaterial {
                suite: actual,
                kind,
            } => {
                assert_eq!(actual.suite_id(), suite.suite_id());
                assert!(kind.contains(expected_kind_fragment));
            }
            other => panic!("expected inert ML-DSA material, got {other:?}"),
        }
    }
    fn signed_roundtrip(suite: MlDsaSuite) {
        let mut rng = hedged_chacha20_rng(
            HedgedRngSeed::from_entropy([suite.suite_id(); 32]),
            b"mldsa-test-keypair",
        );
        let mut sign_rng = hedged_chacha20_rng(
            HedgedRngSeed::from_entropy([suite.suite_id().wrapping_add(1); 32]),
            b"mldsa-test-sign",
        );
        let kp = generate_mldsa_keypair(suite, &mut rng)
            .expect("ML-DSA keypair generation should succeed");
        let message = b"SoraNet PQ harness";
        let context = b"soranet-pq:test";
        let signature =
            sign_mldsa(suite, kp.secret_key(), context, message, &mut sign_rng).unwrap();
        verify_mldsa(
            suite,
            kp.public_key(),
            context,
            message,
            signature.as_bytes(),
        )
        .unwrap();
    }
    #[test]
    fn roundtrip_44() {
        signed_roundtrip(MlDsaSuite::MlDsa44);
    }
    #[test]
    fn roundtrip_65() {
        signed_roundtrip(MlDsaSuite::MlDsa65);
    }
    #[test]
    fn roundtrip_87() {
        signed_roundtrip(MlDsaSuite::MlDsa87);
    }
    #[test]
    fn from_os_helpers_sign_and_verify() {
        let suite = MlDsaSuite::MlDsa44;
        let keypair =
            generate_mldsa_keypair_from_os(suite).expect("OS-backed ML-DSA keypair generation");
        let message = b"OS-backed ML-DSA signing";
        let signature = sign_mldsa_from_os(suite, keypair.secret_key(), b"", message)
            .expect("OS-backed ML-DSA signing");
        verify_mldsa(
            suite,
            keypair.public_key(),
            b"",
            message,
            signature.as_bytes(),
        )
        .expect("OS-backed ML-DSA signature verifies");
    }
    #[test]
    fn from_rng_keypair_reports_seed_failure() {
        let mut rng = FailingPqSeedRng;
        match generate_mldsa_keypair_from_rng(MlDsaSuite::MlDsa44, &mut rng) {
            Err(MlDsaError::Rng(RngError)) => {}
            Ok(_) => panic!("ML-DSA keypair seed RNG failure must be reported"),
            Err(other) => panic!("expected ML-DSA RNG error, got {other:?}"),
        }
    }
    #[test]
    fn from_rng_keypair_rejects_all_zero_seed_material() {
        let mut rng = FixedPqSeedRng { seed: [0_u8; 32] };
        match generate_mldsa_keypair_from_rng(MlDsaSuite::MlDsa44, &mut rng) {
            Err(MlDsaError::Rng(RngError)) => {}
            Ok(_) => panic!("ML-DSA keypair all-zero seed material must be rejected"),
            Err(other) => panic!("expected ML-DSA inert seed RNG error, got {other:?}"),
        }
    }
    #[test]
    fn from_rng_signing_reports_seed_failure() {
        let suite = MlDsaSuite::MlDsa44;
        let keypair = seeded_keypair(suite, 0xA4, b"failing-sign-seed-keygen");
        let mut rng = FailingPqSeedRng;
        match sign_mldsa_from_rng(suite, keypair.secret_key(), b"", b"message", &mut rng) {
            Err(MlDsaError::Rng(RngError)) => {}
            Ok(_) => panic!("ML-DSA signing seed RNG failure must be reported"),
            Err(other) => panic!("expected ML-DSA signing RNG error, got {other:?}"),
        }
    }
    #[test]
    fn from_rng_signing_rejects_all_zero_seed_material() {
        let suite = MlDsaSuite::MlDsa44;
        let keypair = seeded_keypair(suite, 0xA5, b"inert-sign-seed-keygen");
        let mut rng = FixedPqSeedRng { seed: [0_u8; 32] };
        match sign_mldsa_from_rng(suite, keypair.secret_key(), b"", b"message", &mut rng) {
            Err(MlDsaError::Rng(RngError)) => {}
            Ok(_) => panic!("ML-DSA signing all-zero seed material must be rejected"),
            Err(other) => panic!("expected ML-DSA inert signing seed error, got {other:?}"),
        }
    }
    #[test]
    fn direct_fips_keypair_rejects_all_zero_seed_material() {
        let suite = MlDsaSuite::MlDsa44;
        let err = generate_mldsa_keypair_from_fips_seed(suite, &[0_u8; 32])
            .expect_err("all-zero ML-DSA FIPS keypair seed must be rejected");
        match err {
            MlDsaError::InertKeyMaterial {
                suite: actual,
                kind,
            } => {
                assert_eq!(actual.suite_id(), suite.suite_id());
                assert_eq!(kind, "ML-DSA keypair seed");
            }
            other => panic!("expected ML-DSA inert FIPS keypair seed error, got {other:?}"),
        }
    }
    #[test]
    fn generated_keypair_validator_rejects_public_secret_mismatch() {
        let suite = MlDsaSuite::MlDsa44;
        let keypair = seeded_keypair(suite, 0xA9, b"generated-keypair-mismatch");
        let mut mismatched = MlDsaKeyPair {
            public_key: keypair.public_key().to_vec(),
            secret_key: Zeroizing::new(keypair.secret_key().to_vec()),
        };
        mismatched.public_key[0] ^= 0x80;
        let err = validate_generated_mldsa_keypair(suite, &mismatched)
            .expect_err("generated ML-DSA keypair mismatch must be rejected");
        assert_secret_key_mismatch(err);
    }
    #[test]
    fn direct_signing_rejects_all_zero_coin_material() {
        let suite = MlDsaSuite::MlDsa44;
        let keypair = seeded_keypair(suite, 0xA8, b"inert-sign-coins-keygen");
        let err = sign_mldsa_from_coins(suite, keypair.secret_key(), b"", b"message", &[0_u8; 32])
            .expect_err("all-zero ML-DSA signing coins must be rejected");
        match err {
            MlDsaError::InertKeyMaterial {
                suite: actual,
                kind,
            } => {
                assert_eq!(actual.suite_id(), suite.suite_id());
                assert_eq!(kind, "ML-DSA signing coins");
            }
            other => panic!("expected ML-DSA inert signing coin error, got {other:?}"),
        }
    }
    #[test]
    fn signature_constructor_preserves_guarded_payload() {
        let suite = MlDsaSuite::MlDsa44;
        let signature = vec![0xA7; suite.signature_len()];
        let wrapped = MlDsaSignature::try_new(suite, signature.clone())
            .expect("nonzero ML-DSA signature should be accepted");
        assert_eq!(wrapped.as_bytes(), signature.as_slice());
    }

    #[test]
    fn signature_debug_output_redacts_payload() {
        let suite = MlDsaSuite::MlDsa44;
        let wrapped = MlDsaSignature::try_new(suite, vec![0xA7; suite.signature_len()])
            .expect("nonzero ML-DSA signature should be accepted");

        assert_eq!(
            format!("{wrapped:?}"),
            "MlDsaSignature { bytes: \"[REDACTED]\" }"
        );
    }

    #[test]
    fn signature_scrub_erases_owned_payload() {
        let suite = MlDsaSuite::MlDsa44;
        let mut wrapped = MlDsaSignature::try_new(suite, vec![0xA7; suite.signature_len()])
            .expect("nonzero ML-DSA signature should be accepted");

        wrapped.zeroize_sensitive_fields();

        assert!(wrapped.as_bytes().is_empty());
    }

    #[test]
    fn signature_into_bytes_transfers_the_guarded_allocation() {
        let suite = MlDsaSuite::MlDsa44;
        let signature = vec![0xA7; suite.signature_len()];
        let wrapped = MlDsaSignature::try_new(suite, signature.clone())
            .expect("nonzero ML-DSA signature should be accepted");
        let guarded_ptr = wrapped.as_bytes().as_ptr();

        let transferred = wrapped.into_bytes();

        assert_eq!(transferred, signature);
        assert_eq!(transferred.as_ptr(), guarded_ptr);
    }

    #[test]
    fn signature_constructor_rejects_all_zero_payload() {
        let suite = MlDsaSuite::MlDsa44;
        let err = MlDsaSignature::try_new(suite, vec![0u8; suite.signature_len()])
            .expect_err("all-zero ML-DSA signature must be rejected");
        assert_inert_key_material(err, suite, "signature");
    }
    #[test]
    fn seeded_keypair_is_deterministic() {
        for suite in [
            MlDsaSuite::MlDsa44,
            MlDsaSuite::MlDsa65,
            MlDsaSuite::MlDsa87,
        ] {
            let seed = HedgedRngSeed::from_entropy([suite.suite_id().wrapping_add(0xD0); 32]);
            let first = generate_mldsa_keypair_from_seed(suite, seed.clone(), b"seeded-keygen")
                .expect("seeded keypair generation should succeed");
            let second = generate_mldsa_keypair_from_seed(suite, seed, b"seeded-keygen")
                .expect("seeded keypair generation should succeed");
            assert_eq!(first.public_key(), second.public_key());
            assert_eq!(first.secret_key(), second.secret_key());
        }
    }
    #[test]
    fn fips_seed_keypair_is_deterministic_and_suite_separated() {
        let seed = [0xD5; 32];
        let keypair_44 = generate_mldsa_keypair_from_fips_seed(MlDsaSuite::MlDsa44, &seed)
            .expect("ML-DSA-44 FIPS seed should generate a keypair");
        let keypair_44_replay = generate_mldsa_keypair_from_fips_seed(MlDsaSuite::MlDsa44, &seed)
            .expect("ML-DSA-44 FIPS seed should replay");
        let keypair_65 = generate_mldsa_keypair_from_fips_seed(MlDsaSuite::MlDsa65, &seed)
            .expect("ML-DSA-65 FIPS seed should generate a keypair");
        assert_eq!(keypair_44.public_key(), keypair_44_replay.public_key());
        assert_eq!(keypair_44.secret_key(), keypair_44_replay.secret_key());
        assert_ne!(
            &keypair_44.public_key()[..32],
            &keypair_65.public_key()[..32]
        );
    }
    #[test]
    fn fips_seed_keypair_rejects_inert_seed() {
        let err = generate_mldsa_keypair_from_fips_seed(MlDsaSuite::MlDsa65, &[0_u8; 32])
            .expect_err("all-zero FIPS key seed must be rejected");
        assert_inert_key_material(err, MlDsaSuite::MlDsa65, "keypair seed");
    }
    #[test]
    fn seeded_keypair_rejects_all_zero_seed_material() {
        for suite in [
            MlDsaSuite::MlDsa44,
            MlDsaSuite::MlDsa65,
            MlDsaSuite::MlDsa87,
        ] {
            let err = generate_mldsa_keypair_from_seed(
                suite,
                HedgedRngSeed::from_entropy([0_u8; 32]),
                b"seeded-keygen",
            )
            .expect_err("all-zero ML-DSA seed material must be rejected");
            match err {
                MlDsaError::InertKeyMaterial {
                    suite: actual,
                    kind,
                } => {
                    assert_eq!(actual.suite_id(), suite.suite_id());
                    assert_eq!(kind, "ML-DSA seed material");
                }
                other => panic!("unexpected ML-DSA all-zero seed error: {other:?}"),
            }
        }
    }
    #[test]
    fn seeded_keypair_personalization_changes_output() {
        for suite in [
            MlDsaSuite::MlDsa44,
            MlDsaSuite::MlDsa65,
            MlDsaSuite::MlDsa87,
        ] {
            let seed = HedgedRngSeed::from_entropy([suite.suite_id().wrapping_add(0xD8); 32]);
            let first = generate_mldsa_keypair_from_seed(suite, seed.clone(), b"seeded-keygen-a")
                .expect("seeded keypair generation should succeed");
            let second = generate_mldsa_keypair_from_seed(suite, seed, b"seeded-keygen-b")
                .expect("seeded keypair generation should succeed");
            assert_ne!(first.public_key(), second.public_key());
            assert_ne!(first.secret_key(), second.secret_key());
        }
    }
    #[test]
    fn deterministic_signing_replays_with_same_seed() {
        let suite = MlDsaSuite::MlDsa65;
        let keypair = generate_mldsa_keypair_from_seed(
            suite,
            HedgedRngSeed::from_entropy([0xE1; 32]),
            b"deterministic-sign-keygen",
        )
        .expect("seeded keypair generation should succeed");
        let mut first_rng = deterministic_chacha20_rng(
            HedgedRngSeed::from_entropy([0xE2; 32]),
            b"deterministic-sign",
        );
        let mut second_rng = deterministic_chacha20_rng(
            HedgedRngSeed::from_entropy([0xE2; 32]),
            b"deterministic-sign",
        );
        let context = b"soranet-pq:deterministic-sign";
        let message = b"repeatable ML-DSA signature";
        let first = sign_mldsa(
            suite,
            keypair.secret_key(),
            context,
            message,
            &mut first_rng,
        )
        .expect("signature succeeds");
        let second = sign_mldsa(
            suite,
            keypair.secret_key(),
            context,
            message,
            &mut second_rng,
        )
        .expect("signature succeeds");
        assert_eq!(first.as_bytes(), second.as_bytes());
        verify_mldsa(
            suite,
            keypair.public_key(),
            context,
            message,
            first.as_bytes(),
        )
        .expect("deterministic signature verifies");
    }
    #[test]
    fn signing_personalization_changes_signature() {
        let suite = MlDsaSuite::MlDsa65;
        let keypair = generate_mldsa_keypair_from_seed(
            suite,
            HedgedRngSeed::from_entropy([0xEA; 32]),
            b"personalized-sign-keygen",
        )
        .expect("seeded keypair generation should succeed");
        let mut first_rng = deterministic_chacha20_rng(
            HedgedRngSeed::from_entropy([0xEB; 32]),
            b"personalized-sign-a",
        );
        let mut second_rng = deterministic_chacha20_rng(
            HedgedRngSeed::from_entropy([0xEB; 32]),
            b"personalized-sign-b",
        );
        let context = b"soranet-pq:personalized-sign";
        let message = b"same message and key, different signing coins";
        let first = sign_mldsa(
            suite,
            keypair.secret_key(),
            context,
            message,
            &mut first_rng,
        )
        .expect("first signature succeeds");
        let second = sign_mldsa(
            suite,
            keypair.secret_key(),
            context,
            message,
            &mut second_rng,
        )
        .expect("second signature succeeds");
        assert_ne!(first.as_bytes(), second.as_bytes());
        verify_mldsa(
            suite,
            keypair.public_key(),
            context,
            message,
            first.as_bytes(),
        )
        .expect("first signature verifies");
        verify_mldsa(
            suite,
            keypair.public_key(),
            context,
            message,
            second.as_bytes(),
        )
        .expect("second signature verifies");
    }
    #[test]
    fn generated_keypairs_and_signatures_match_suite_lengths() {
        for suite in [
            MlDsaSuite::MlDsa44,
            MlDsaSuite::MlDsa65,
            MlDsaSuite::MlDsa87,
        ] {
            let keypair = generate_mldsa_keypair_from_seed(
                suite,
                HedgedRngSeed::from_entropy([suite.suite_id().wrapping_add(0xEC); 32]),
                b"length-keygen",
            )
            .expect("seeded keypair generation should succeed");
            let mut rng = deterministic_chacha20_rng(
                HedgedRngSeed::from_entropy([suite.suite_id().wrapping_add(0xEF); 32]),
                b"length-sign",
            );
            let signature = sign_mldsa(suite, keypair.secret_key(), b"", b"length-check", &mut rng)
                .expect("signature succeeds");
            assert_eq!(keypair.public_key().len(), suite.public_key_len());
            assert_eq!(keypair.secret_key().len(), suite.secret_key_len());
            assert_eq!(signature.as_bytes().len(), suite.signature_len());
        }
    }
    #[test]
    fn keypair_debug_output_redacts_secret_material() {
        let keypair = MlDsaKeyPair {
            public_key: vec![0x11; 2],
            secret_key: Zeroizing::new(vec![0xA5; 3]),
        };
        assert_eq!(
            format!("{keypair:?}"),
            "MlDsaKeyPair { public_key_len: 2, secret_key: \"[REDACTED]\" }"
        );
    }
    #[test]
    fn sign_rejects_invalid_secret_key_length() {
        let mut rng = deterministic_chacha20_rng(
            HedgedRngSeed::from_entropy([0xE3; 32]),
            b"invalid-secret-sign",
        );
        let err = sign_mldsa(MlDsaSuite::MlDsa44, &[0u8; 8], b"", b"message", &mut rng)
            .expect_err("short secret must fail");
        match err {
            MlDsaError::BadEncoding(err) => assert!(err.kind.contains("secret key")),
            other => panic!("unexpected error: {other:?}"),
        }
    }
    #[test]
    fn sign_helpers_reject_invalid_inputs_before_entropy() {
        let suite = MlDsaSuite::MlDsa44;
        let mut rng = deterministic_chacha20_rng(
            HedgedRngSeed::from_entropy([0xE7; 32]),
            b"invalid-sign-preflight",
        );
        let short_secret = [0u8; 8];
        let oversized_context = vec![0xA5; ML_DSA_CONTEXT_MAX_LEN + 1];
        let err = sign_mldsa(suite, &short_secret, b"", b"message", &mut rng)
            .expect_err("short direct secret must fail before signing coins are used");
        match err {
            MlDsaError::BadEncoding(err) => assert!(err.kind.contains("secret key")),
            other => panic!("unexpected direct secret result: {other:?}"),
        }
        let err = sign_mldsa_from_os(suite, &short_secret, b"", b"message")
            .expect_err("short OS helper secret must fail before OS entropy");
        match err {
            MlDsaError::BadEncoding(err) => assert!(err.kind.contains("secret key")),
            other => panic!("unexpected OS helper secret result: {other:?}"),
        }
        let err = sign_mldsa(
            suite,
            &short_secret,
            &oversized_context,
            b"message",
            &mut rng,
        )
        .expect_err("oversized context must fail before secret decoding");
        assert!(matches!(
            err,
            MlDsaError::ContextTooLong {
                len
            } if len == ML_DSA_CONTEXT_MAX_LEN + 1
        ));
        let err = sign_mldsa_from_os(suite, &short_secret, &oversized_context, b"message")
            .expect_err("oversized OS helper context must fail before OS entropy");
        assert!(matches!(
            err,
            MlDsaError::ContextTooLong {
                len
            } if len == ML_DSA_CONTEXT_MAX_LEN + 1
        ));
    }
    #[test]
    fn verify_rejects_invalid_public_key_and_signature_lengths() {
        let suite = MlDsaSuite::MlDsa44;
        let keypair = generate_mldsa_keypair_from_seed(
            suite,
            HedgedRngSeed::from_entropy([0xE4; 32]),
            b"invalid-verify-keygen",
        )
        .expect("seeded keypair generation should succeed");
        let err = verify_mldsa(suite, &[0u8; 8], b"", b"message", &[0u8; 1])
            .expect_err("short public key must fail");
        match err {
            MlDsaError::BadEncoding(err) => assert!(err.kind.contains("public key")),
            other => panic!("unexpected error: {other:?}"),
        }
        let err = verify_mldsa(suite, keypair.public_key(), b"", b"message", &[0u8; 8])
            .expect_err("short signature must fail");
        match err {
            MlDsaError::BadEncoding(err) => assert!(err.kind.contains("signature")),
            other => panic!("unexpected error: {other:?}"),
        }
    }
    #[test]
    fn suite_validation_helpers_reject_wrong_lengths() {
        let suite = MlDsaSuite::MlDsa65;
        let keypair = seeded_keypair(suite, 0xD5, b"validation-helper-keygen");
        let mut rng = deterministic_chacha20_rng(
            HedgedRngSeed::from_entropy([0xD5; 32]),
            b"validation-helper-sign",
        );
        let signature = sign_mldsa(
            suite,
            keypair.secret_key(),
            b"",
            b"validation-helper",
            &mut rng,
        )
        .expect("generated signature");
        for (label, err) in [
            (
                "public key",
                suite.validate_public_key(&vec![0u8; suite.public_key_len() - 1]),
            ),
            (
                "secret key",
                suite.validate_secret_key(&vec![0u8; suite.secret_key_len() - 1]),
            ),
            (
                "signature",
                suite.validate_signature(&vec![0u8; suite.signature_len() - 1]),
            ),
        ] {
            let err = err.expect_err("short ML-DSA material must fail");
            match err {
                MlDsaError::BadEncoding(err) => assert!(err.to_string().contains(label)),
                other => panic!("unexpected error: {other:?}"),
            }
        }
        validate_mldsa_public_key(suite, keypair.public_key()).expect("generated public key");
        validate_mldsa_secret_key(suite, keypair.secret_key()).expect("generated secret key");
        validate_mldsa_signature(suite, signature.as_bytes()).expect("generated signature");
        let err = validate_mldsa_secret_key(suite, &vec![0u8; suite.secret_key_len()])
            .expect_err("length-valid but inconsistent secret key must fail");
        assert_inert_key_material(err, suite, "secret key");
    }
    #[test]
    fn validation_rejects_all_zero_public_key_material() {
        for suite in [
            MlDsaSuite::MlDsa44,
            MlDsaSuite::MlDsa65,
            MlDsaSuite::MlDsa87,
        ] {
            let keypair = seeded_keypair(
                suite,
                suite.suite_id().wrapping_add(0x11),
                b"zero-public-keypair",
            );
            let mut rng = deterministic_chacha20_rng(
                HedgedRngSeed::from_entropy([suite.suite_id().wrapping_add(0x12); 32]),
                b"zero-public-sign",
            );
            let message = b"zero public key";
            let signature = sign_mldsa(suite, keypair.secret_key(), b"", message, &mut rng)
                .expect("signature succeeds");
            let public_key = vec![0u8; suite.public_key_len()];
            let err = validate_mldsa_public_key(suite, &public_key)
                .expect_err("all-zero public key material must fail");
            assert_inert_key_material(err, suite, "public key");
            let err = verify_mldsa(suite, &public_key, b"", message, signature.as_bytes())
                .expect_err("all-zero public key must fail before verification");
            assert_inert_key_material(err, suite, "public key");
        }
    }
    #[test]
    fn validation_rejects_all_zero_secret_key_material() {
        for suite in [
            MlDsaSuite::MlDsa44,
            MlDsaSuite::MlDsa65,
            MlDsaSuite::MlDsa87,
        ] {
            let secret_key = vec![0u8; suite.secret_key_len()];
            let err = validate_mldsa_secret_key(suite, &secret_key)
                .expect_err("all-zero secret key material must fail validation");
            assert_inert_key_material(err, suite, "secret key");
            let err = mldsa_public_key_from_secret_key(suite, &secret_key)
                .expect_err("all-zero secret key must not reconstruct public material");
            assert_inert_key_material(err, suite, "secret key");
            let mut rng = deterministic_chacha20_rng(
                HedgedRngSeed::from_entropy([suite.suite_id().wrapping_add(0x13); 32]),
                b"zero-secret-sign",
            );
            let err = sign_mldsa(suite, &secret_key, b"", b"message", &mut rng)
                .expect_err("all-zero secret key must fail direct signing");
            assert_inert_key_material(err, suite, "secret key");
            let mut failing_rng = FailingPqSeedRng;
            let err = sign_mldsa_from_rng(suite, &secret_key, b"", b"message", &mut failing_rng)
                .expect_err("all-zero secret key must fail before RNG seeding");
            assert_inert_key_material(err, suite, "secret key");
        }
    }
    #[test]
    fn validation_rejects_all_zero_signature_material() {
        for suite in [
            MlDsaSuite::MlDsa44,
            MlDsaSuite::MlDsa65,
            MlDsaSuite::MlDsa87,
        ] {
            let keypair = seeded_keypair(
                suite,
                suite.suite_id().wrapping_add(0x14),
                b"zero-signature-keypair",
            );
            let signature = vec![0u8; suite.signature_len()];
            let err = validate_mldsa_signature(suite, &signature)
                .expect_err("all-zero signature material must fail");
            assert_inert_key_material(err, suite, "signature");
            let err = verify_mldsa(suite, keypair.public_key(), b"", b"message", &signature)
                .expect_err("all-zero signature must fail before verification");
            assert_inert_key_material(err, suite, "signature");
        }
    }
    #[test]
    fn secret_key_reconstruction_matches_generated_public_key() {
        for suite in [
            MlDsaSuite::MlDsa44,
            MlDsaSuite::MlDsa65,
            MlDsaSuite::MlDsa87,
        ] {
            let keypair = seeded_keypair(
                suite,
                suite.suite_id().wrapping_add(0x70),
                b"secret-reconstruction",
            );
            suite
                .validate_secret_key(keypair.secret_key())
                .expect("generated secret key validates");
            assert_eq!(
                suite
                    .public_key_from_secret_key(keypair.secret_key())
                    .expect("public key reconstructs"),
                keypair.public_key()
            );
            assert_eq!(
                mldsa_public_key_from_secret_key(suite, keypair.secret_key())
                    .expect("free helper reconstructs public key"),
                keypair.public_key()
            );
        }
    }
    #[test]
    fn secret_key_validation_rejects_tr_drift() {
        let suite = MlDsaSuite::MlDsa65;
        let keypair = seeded_keypair(suite, 0xD6, b"secret-tr-drift");
        let mut secret_key = keypair.secret_key().to_vec();
        secret_key[ML_DSA_SECRET_TR_OFFSET] ^= 0x01;
        let err = suite
            .validate_secret_key(&secret_key)
            .expect_err("corrupted tr must fail secret-key validation");
        assert_secret_key_mismatch(err);
    }
    #[test]
    fn secret_key_validation_rejects_t0_drift() {
        let suite = MlDsaSuite::MlDsa65;
        let keypair = seeded_keypair(suite, 0xD7, b"secret-t0-drift");
        let mut secret_key = keypair.secret_key().to_vec();
        let last = secret_key
            .last_mut()
            .expect("generated secret key is nonempty");
        *last ^= 0x01;
        let err = suite
            .validate_secret_key(&secret_key)
            .expect_err("corrupted t0 must fail secret-key validation");
        assert_secret_key_mismatch(err);
    }
    #[test]
    fn signing_rejects_secret_key_tr_drift() {
        let suite = MlDsaSuite::MlDsa44;
        let keypair = seeded_keypair(suite, 0xD8, b"sign-secret-tr-drift");
        let mut secret_key = keypair.secret_key().to_vec();
        secret_key[ML_DSA_SECRET_TR_OFFSET] ^= 0x80;
        let mut rng = deterministic_chacha20_rng(
            HedgedRngSeed::from_entropy([0xD9; 32]),
            b"sign-secret-tr-drift-rng",
        );
        let err = sign_mldsa(suite, &secret_key, b"", b"message", &mut rng)
            .expect_err("direct signing must reject corrupted secret key");
        assert_secret_key_mismatch(err);
        let err = sign_mldsa_from_os(suite, &secret_key, b"", b"message")
            .expect_err("OS-backed signing must reject corrupted secret key");
        assert_secret_key_mismatch(err);
    }
    #[test]
    fn bad_encoding_display_includes_kind_and_lengths() {
        let err = verify_mldsa(MlDsaSuite::MlDsa65, &[0u8; 9], b"", b"message", &[0u8; 8])
            .expect_err("short public key must fail before signature decoding");
        let rendered = err.to_string();
        assert!(rendered.contains("ML-DSA-65 public key"));
        assert!(rendered.contains('9'));
        assert!(rendered.contains("1952"));
    }
    #[test]
    fn max_context_length_signs_and_verifies() {
        let suite = MlDsaSuite::MlDsa44;
        let keypair = generate_mldsa_keypair_from_seed(
            suite,
            HedgedRngSeed::from_entropy([0xE5; 32]),
            b"max-context-keygen",
        )
        .expect("seeded keypair generation should succeed");
        let mut rng = deterministic_chacha20_rng(
            HedgedRngSeed::from_entropy([0xE6; 32]),
            b"max-context-sign",
        );
        let context = vec![0xA5; ML_DSA_CONTEXT_MAX_LEN];
        let message = b"maximum context length";
        let signature = sign_mldsa(suite, keypair.secret_key(), &context, message, &mut rng)
            .expect("max context signs");
        verify_mldsa(
            suite,
            keypair.public_key(),
            &context,
            message,
            signature.as_bytes(),
        )
        .expect("max context verifies");
    }
    #[test]
    fn empty_context_and_message_sign_and_verify() {
        let suite = MlDsaSuite::MlDsa87;
        let keypair = generate_mldsa_keypair_from_seed(
            suite,
            HedgedRngSeed::from_entropy([0xF4; 32]),
            b"empty-message-keygen",
        )
        .expect("seeded keypair generation should succeed");
        let mut rng = deterministic_chacha20_rng(
            HedgedRngSeed::from_entropy([0xF5; 32]),
            b"empty-message-sign",
        );
        let signature = sign_mldsa(suite, keypair.secret_key(), b"", b"", &mut rng)
            .expect("empty message signs");
        verify_mldsa(suite, keypair.public_key(), b"", b"", signature.as_bytes())
            .expect("empty message verifies");
    }
    #[test]
    fn suite_ids_roundtrip_and_reject_unknown() {
        for suite in [
            MlDsaSuite::MlDsa44,
            MlDsaSuite::MlDsa65,
            MlDsaSuite::MlDsa87,
        ] {
            assert!(suite.public_key_len() > 0);
            assert!(suite.secret_key_len() > suite.public_key_len());
            assert!(suite.signature_len() > 0);
            assert!(matches!(
                MlDsaSuite::from_suite_id(suite.suite_id()),
                Some(recovered) if recovered.suite_id() == suite.suite_id()
            ));
        }
        assert!(MlDsaSuite::from_suite_id(0xFF).is_none());
    }
    #[test]
    fn context_length_is_checked_before_sign_and_verify() {
        let mut rng = hedged_chacha20_rng(
            HedgedRngSeed::from_entropy([0x87; 32]),
            b"mldsa-context-limit-keypair",
        );
        let mut sign_rng = hedged_chacha20_rng(
            HedgedRngSeed::from_entropy([0x88; 32]),
            b"mldsa-context-limit-sign",
        );
        let kp = generate_mldsa_keypair(MlDsaSuite::MlDsa44, &mut rng)
            .expect("ML-DSA keypair generation should succeed");
        let context = vec![0u8; ML_DSA_CONTEXT_MAX_LEN + 1];
        let sign_err = sign_mldsa(
            MlDsaSuite::MlDsa44,
            kp.secret_key(),
            &context,
            b"message",
            &mut sign_rng,
        )
        .unwrap_err();
        assert!(matches!(
            sign_err,
            MlDsaError::ContextTooLong {
                len
            } if len == ML_DSA_CONTEXT_MAX_LEN + 1
        ));
        let verify_err = verify_mldsa(
            MlDsaSuite::MlDsa44,
            kp.public_key(),
            &context,
            b"message",
            &[0u8; 1],
        )
        .unwrap_err();
        assert!(matches!(
            verify_err,
            MlDsaError::ContextTooLong {
                len
            } if len == ML_DSA_CONTEXT_MAX_LEN + 1
        ));
    }
    #[test]
    fn sign_rejects_long_context_before_bad_secret_length() {
        let mut sign_rng = deterministic_chacha20_rng(
            HedgedRngSeed::from_entropy([0xF0; 32]),
            b"mldsa-context-before-secret",
        );
        let context = vec![0u8; ML_DSA_CONTEXT_MAX_LEN + 1];
        let err = sign_mldsa(
            MlDsaSuite::MlDsa44,
            &[],
            &context,
            b"message",
            &mut sign_rng,
        )
        .expect_err("context length must be checked before secret length");
        assert!(matches!(
            err,
            MlDsaError::ContextTooLong {
                len
            } if len == ML_DSA_CONTEXT_MAX_LEN + 1
        ));
    }
    #[test]
    fn verify_rejects_long_context_before_bad_key_lengths() {
        let context = vec![0u8; ML_DSA_CONTEXT_MAX_LEN + 1];
        let err = verify_mldsa(MlDsaSuite::MlDsa44, &[], &context, b"message", &[])
            .expect_err("context length must be checked first");
        assert!(matches!(
            err,
            MlDsaError::ContextTooLong {
                len
            } if len == ML_DSA_CONTEXT_MAX_LEN + 1
        ));
    }
    #[test]
    fn context_too_long_display_includes_length() {
        let err = MlDsaError::ContextTooLong { len: 300 };
        assert_eq!(
            err.to_string(),
            "ML-DSA context length must be at most 255 bytes, found 300"
        );
    }
    #[test]
    fn reject_modified_message() {
        let mut rng = hedged_chacha20_rng(
            HedgedRngSeed::from_entropy([0x44; 32]),
            b"mldsa-modified-keypair",
        );
        let mut sign_rng = hedged_chacha20_rng(
            HedgedRngSeed::from_entropy([0x45; 32]),
            b"mldsa-modified-sign",
        );
        let kp = generate_mldsa_keypair(MlDsaSuite::MlDsa44, &mut rng)
            .expect("ML-DSA keypair generation should succeed");
        let message = b"context";
        let context = b"soranet-pq:test";
        let signature = sign_mldsa(
            MlDsaSuite::MlDsa44,
            kp.secret_key(),
            context,
            message,
            &mut sign_rng,
        )
        .unwrap();
        let mut tampered = message.to_vec();
        tampered[0] ^= 0xFF;
        let err = verify_mldsa(
            MlDsaSuite::MlDsa44,
            kp.public_key(),
            context,
            &tampered,
            signature.as_bytes(),
        )
        .unwrap_err();
        match err {
            MlDsaError::VerificationFailed(VerificationError::InvalidSignature) => {}
            _ => panic!("unexpected error"),
        }
    }
    #[test]
    fn reject_modified_signature() {
        let suite = MlDsaSuite::MlDsa65;
        let keypair = generate_mldsa_keypair_from_seed(
            suite,
            HedgedRngSeed::from_entropy([0xF6; 32]),
            b"modified-signature-keypair",
        )
        .expect("seeded keypair generation should succeed");
        let mut sign_rng = deterministic_chacha20_rng(
            HedgedRngSeed::from_entropy([0xF7; 32]),
            b"modified-signature-sign",
        );
        let message = b"signature tamper target";
        let mut signature = sign_mldsa(suite, keypair.secret_key(), b"", message, &mut sign_rng)
            .expect("signature succeeds")
            .as_bytes()
            .to_vec();
        signature[0] ^= 0x01;
        let err = verify_mldsa(suite, keypair.public_key(), b"", message, &signature)
            .expect_err("modified signature must fail");
        assert!(matches!(
            err,
            MlDsaError::VerificationFailed(VerificationError::InvalidSignature)
        ));
    }
    #[test]
    fn reject_wrong_public_key() {
        let suite = MlDsaSuite::MlDsa65;
        let signing_keypair = generate_mldsa_keypair_from_seed(
            suite,
            HedgedRngSeed::from_entropy([0xF1; 32]),
            b"wrong-public-key-signing",
        )
        .expect("signing keypair generation should succeed");
        let verifying_keypair = generate_mldsa_keypair_from_seed(
            suite,
            HedgedRngSeed::from_entropy([0xF2; 32]),
            b"wrong-public-key-verifying",
        )
        .expect("verifying keypair generation should succeed");
        let mut sign_rng = deterministic_chacha20_rng(
            HedgedRngSeed::from_entropy([0xF3; 32]),
            b"wrong-public-key-sign",
        );
        let message = b"wrong public key must not verify";
        let context = b"soranet-pq:test";
        let signature = sign_mldsa(
            suite,
            signing_keypair.secret_key(),
            context,
            message,
            &mut sign_rng,
        )
        .expect("signature succeeds");
        let err = verify_mldsa(
            suite,
            verifying_keypair.public_key(),
            context,
            message,
            signature.as_bytes(),
        )
        .expect_err("signature must fail under a different public key");
        assert!(matches!(
            err,
            MlDsaError::VerificationFailed(VerificationError::InvalidSignature)
        ));
    }
    #[test]
    fn context_is_domain_separating() {
        let mut rng = hedged_chacha20_rng(
            HedgedRngSeed::from_entropy([0x65; 32]),
            b"mldsa-context-keypair",
        );
        let mut sign_rng = hedged_chacha20_rng(
            HedgedRngSeed::from_entropy([0x66; 32]),
            b"mldsa-context-sign",
        );
        let kp = generate_mldsa_keypair(MlDsaSuite::MlDsa65, &mut rng)
            .expect("ML-DSA keypair generation should succeed");
        let message = b"context-bound message";
        let signature = sign_mldsa(
            MlDsaSuite::MlDsa65,
            kp.secret_key(),
            b"context-a",
            message,
            &mut sign_rng,
        )
        .unwrap();
        assert!(
            verify_mldsa(
                MlDsaSuite::MlDsa65,
                kp.public_key(),
                b"context-b",
                message,
                signature.as_bytes(),
            )
            .is_err()
        );
    }
}

#[cfg(test)]
mod fips204_nistkat_tests;
