use crate::{
    HedgedChaCha20Rng, HedgedRngSeed, RngError, deterministic_chacha20_rng,
    hedged_chacha20_rng_from_rng,
};
use core::{fmt, str::FromStr};
use pqcrypto_mlkem as _;
use pqcrypto_traits::Error as PqError;
use rand_core::{RngCore, TryCryptoRng};
use sha3::{Digest, Sha3_256};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};
const MLKEM512_PUBLIC_KEY_BYTES: usize = 800;
const MLKEM512_SECRET_KEY_BYTES: usize = 1632;
const MLKEM512_CIPHERTEXT_BYTES: usize = 768;
const MLKEM512_SHARED_SECRET_BYTES: usize = 32;
const MLKEM768_PUBLIC_KEY_BYTES: usize = 1184;
const MLKEM768_SECRET_KEY_BYTES: usize = 2400;
const MLKEM768_CIPHERTEXT_BYTES: usize = 1088;
const MLKEM768_SHARED_SECRET_BYTES: usize = 32;
const MLKEM1024_PUBLIC_KEY_BYTES: usize = 1568;
const MLKEM1024_SECRET_KEY_BYTES: usize = 3168;
const MLKEM1024_CIPHERTEXT_BYTES: usize = 1568;
const MLKEM1024_SHARED_SECRET_BYTES: usize = 32;
const MLKEM_PUBLIC_KEY_HASH_BYTES: usize = 32;
const MLKEM_IMPLICIT_REJECTION_SEED_BYTES: usize = 32;
const MLKEM_PUBLIC_KEY_SEED_BYTES: usize = 32;
const MLKEM_FIELD_MODULUS: u16 = 3329;
/// Supported ML-KEM parameter sets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MlKemSuite {
    /// ML-KEM-512 as specified in FIPS 203.
    MlKem512,
    /// ML-KEM-768 as specified in FIPS 203.
    MlKem768,
    /// ML-KEM-1024 as specified in FIPS 203.
    MlKem1024,
}
impl MlKemSuite {
    /// All supported parameter sets ordered by ascending security level.
    pub const ALL: [Self; 3] = [Self::MlKem512, Self::MlKem768, Self::MlKem1024];
    /// Identifier used inside `SoraNet` capability TLVs for this parameter set.
    #[must_use]
    pub const fn kem_id(self) -> u8 {
        match self {
            MlKemSuite::MlKem512 => 0,
            MlKemSuite::MlKem768 => 1,
            MlKemSuite::MlKem1024 => 2,
        }
    }
    /// Look up a suite by its capability identifier.
    #[must_use]
    pub const fn from_kem_id(id: u8) -> Option<Self> {
        match id {
            0 => Some(MlKemSuite::MlKem512),
            1 => Some(MlKemSuite::MlKem768),
            2 => Some(MlKemSuite::MlKem1024),
            _ => None,
        }
    }
    /// Return the public key length in bytes for this parameter set.
    #[must_use]
    pub const fn public_key_len(self) -> usize {
        match self {
            MlKemSuite::MlKem512 => MLKEM512_PUBLIC_KEY_BYTES,
            MlKemSuite::MlKem768 => MLKEM768_PUBLIC_KEY_BYTES,
            MlKemSuite::MlKem1024 => MLKEM1024_PUBLIC_KEY_BYTES,
        }
    }
    /// Return the secret key length in bytes for this parameter set.
    #[must_use]
    pub const fn secret_key_len(self) -> usize {
        match self {
            MlKemSuite::MlKem512 => MLKEM512_SECRET_KEY_BYTES,
            MlKemSuite::MlKem768 => MLKEM768_SECRET_KEY_BYTES,
            MlKemSuite::MlKem1024 => MLKEM1024_SECRET_KEY_BYTES,
        }
    }
    /// Return the ciphertext length in bytes for this parameter set.
    #[must_use]
    pub const fn ciphertext_len(self) -> usize {
        match self {
            MlKemSuite::MlKem512 => MLKEM512_CIPHERTEXT_BYTES,
            MlKemSuite::MlKem768 => MLKEM768_CIPHERTEXT_BYTES,
            MlKemSuite::MlKem1024 => MLKEM1024_CIPHERTEXT_BYTES,
        }
    }
    /// Return the shared-secret length in bytes for this parameter set.
    #[must_use]
    pub const fn shared_secret_len(self) -> usize {
        match self {
            MlKemSuite::MlKem512 => MLKEM512_SHARED_SECRET_BYTES,
            MlKemSuite::MlKem768 => MLKEM768_SHARED_SECRET_BYTES,
            MlKemSuite::MlKem1024 => MLKEM1024_SHARED_SECRET_BYTES,
        }
    }
    /// Return the full tuple of byte lengths for this parameter set.
    ///
    /// # Examples
    ///
    /// ```
    /// use soranet_pq::MlKemSuite;
    ///
    /// let params = MlKemSuite::MlKem512.parameters();
    /// assert_eq!(params.public_key, MlKemSuite::MlKem512.public_key_len());
    /// assert_eq!(params.secret_key, MlKemSuite::MlKem512.secret_key_len());
    /// assert_eq!(params.ciphertext, MlKemSuite::MlKem512.ciphertext_len());
    /// assert_eq!(
    ///     params.shared_secret,
    ///     MlKemSuite::MlKem512.shared_secret_len()
    /// );
    /// ```
    #[must_use]
    pub fn parameters(self) -> MlKemParameters {
        match self {
            MlKemSuite::MlKem512 => MlKemParameters {
                public_key: MLKEM512_PUBLIC_KEY_BYTES,
                secret_key: MLKEM512_SECRET_KEY_BYTES,
                ciphertext: MLKEM512_CIPHERTEXT_BYTES,
                shared_secret: MLKEM512_SHARED_SECRET_BYTES,
            },
            MlKemSuite::MlKem768 => MlKemParameters {
                public_key: MLKEM768_PUBLIC_KEY_BYTES,
                secret_key: MLKEM768_SECRET_KEY_BYTES,
                ciphertext: MLKEM768_CIPHERTEXT_BYTES,
                shared_secret: MLKEM768_SHARED_SECRET_BYTES,
            },
            MlKemSuite::MlKem1024 => MlKemParameters {
                public_key: MLKEM1024_PUBLIC_KEY_BYTES,
                secret_key: MLKEM1024_SECRET_KEY_BYTES,
                ciphertext: MLKEM1024_CIPHERTEXT_BYTES,
                shared_secret: MLKEM1024_SHARED_SECRET_BYTES,
            },
        }
    }
    /// Validate a public key encoding for this suite.
    ///
    /// # Errors
    /// Returns an error when the byte string has the wrong length, is inert
    /// all-zero material, or contains noncanonical polynomial coefficients.
    pub fn validate_public_key(self, bytes: &[u8]) -> Result<(), MlKemError> {
        validate_len(self.public_key_kind(), bytes.len(), self.public_key_len())?;
        self.validate_key_material_not_all_zero(self.public_key_kind(), bytes)?;
        self.validate_public_key_canonical(bytes)
    }
    /// Validate a secret key encoding for this suite.
    ///
    /// # Errors
    /// Returns an error when the byte string has the wrong length, is inert
    /// all-zero material, its private component is noncanonical, or its embedded
    /// public key is inert, noncanonical, or inconsistent with its `H(ek)` hash,
    /// or its implicit-rejection seed is inert all-zero material.
    pub fn validate_secret_key(self, bytes: &[u8]) -> Result<(), MlKemError> {
        self.validate_secret_key_len(bytes)?;
        self.validate_key_material_not_all_zero(self.secret_key_kind(), bytes)?;
        self.validate_secret_key_private_component(bytes)?;
        let embedded_public = self.public_key_from_validated_secret_key(bytes);
        self.validate_key_material_not_all_zero(
            self.secret_key_embedded_public_kind(),
            embedded_public,
        )?;
        self.validate_public_key_canonical(embedded_public)?;
        self.validate_secret_key_public_hash(bytes)?;
        self.validate_key_material_not_all_zero(
            self.secret_key_implicit_rejection_seed_kind(),
            self.implicit_rejection_seed_from_validated_secret_key(bytes),
        )
    }
    /// Validate a ciphertext encoding for this suite.
    ///
    /// # Errors
    /// Returns an error when the byte string has the wrong length or is inert all-zero material.
    pub fn validate_ciphertext(self, bytes: &[u8]) -> Result<(), MlKemError> {
        validate_len(self.ciphertext_kind(), bytes.len(), self.ciphertext_len())?;
        self.validate_key_material_not_all_zero(self.ciphertext_kind(), bytes)
    }
    /// Return the public key embedded in a FIPS 203 decapsulation key.
    ///
    /// ML-KEM decapsulation keys contain the matching encapsulation key near the end of the
    /// secret-key byte string, followed by `H(ek)` and the implicit rejection seed. This helper
    /// lets callers fail closed on mismatched public/secret material before implicit rejection
    /// produces a traffic-key mismatch at runtime.
    ///
    /// # Errors
    /// Returns an error when the secret-key byte string has the wrong length or its private
    /// component or embedded public key/hash fields are noncanonical or internally inconsistent.
    pub fn public_key_from_secret_key(self, secret_key: &[u8]) -> Result<&[u8], MlKemError> {
        self.validate_secret_key(secret_key)?;
        Ok(self.public_key_from_validated_secret_key(secret_key))
    }
    /// Return the public-key hash embedded in a FIPS 203 decapsulation key.
    ///
    /// # Errors
    /// Returns an error when the secret-key byte string has the wrong length or its private
    /// component or embedded public key/hash fields are noncanonical or internally inconsistent.
    pub fn public_key_hash_from_secret_key(self, secret_key: &[u8]) -> Result<&[u8], MlKemError> {
        self.validate_secret_key(secret_key)?;
        Ok(self.public_key_hash_from_validated_secret_key(secret_key))
    }
    /// Validate that a public key and secret key belong to the same ML-KEM key pair.
    ///
    /// # Errors
    /// Returns [`MlKemError::BadEncoding`] for malformed lengths and
    /// [`MlKemError::NonCanonicalEncoding`] for noncanonical public-key field
    /// coefficients, [`MlKemError::KeyPairMismatch`] when the secret key embeds
    /// a different public key, or [`MlKemError::KeyPairPublicHashMismatch`]
    /// when its embedded `H(ek)` value does not match the public key.
    pub fn validate_key_pair(self, public_key: &[u8], secret_key: &[u8]) -> Result<(), MlKemError> {
        self.validate_public_key(public_key)?;
        self.validate_secret_key(secret_key)?;
        let embedded_public = self.public_key_from_validated_secret_key(secret_key);
        if embedded_public != public_key {
            return Err(MlKemError::KeyPairMismatch {
                suite: self,
                kind: self.key_pair_kind(),
            });
        }
        let embedded_public_hash = self.public_key_hash_from_validated_secret_key(secret_key);
        if embedded_public_hash != mlkem_public_key_hash(public_key).as_slice() {
            return Err(MlKemError::KeyPairPublicHashMismatch {
                suite: self,
                kind: self.key_pair_hash_kind(),
            });
        }
        Ok(())
    }
    const fn public_key_kind(self) -> &'static str {
        match self {
            MlKemSuite::MlKem512 => "ML-KEM-512 public key",
            MlKemSuite::MlKem768 => "ML-KEM-768 public key",
            MlKemSuite::MlKem1024 => "ML-KEM-1024 public key",
        }
    }
    const fn secret_key_kind(self) -> &'static str {
        match self {
            MlKemSuite::MlKem512 => "ML-KEM-512 secret key",
            MlKemSuite::MlKem768 => "ML-KEM-768 secret key",
            MlKemSuite::MlKem1024 => "ML-KEM-1024 secret key",
        }
    }
    const fn ciphertext_kind(self) -> &'static str {
        match self {
            MlKemSuite::MlKem512 => "ML-KEM-512 ciphertext",
            MlKemSuite::MlKem768 => "ML-KEM-768 ciphertext",
            MlKemSuite::MlKem1024 => "ML-KEM-1024 ciphertext",
        }
    }
    const fn shared_secret_kind(self) -> &'static str {
        match self {
            MlKemSuite::MlKem512 => "ML-KEM-512 shared secret",
            MlKemSuite::MlKem768 => "ML-KEM-768 shared secret",
            MlKemSuite::MlKem1024 => "ML-KEM-1024 shared secret",
        }
    }
    const fn key_pair_kind(self) -> &'static str {
        match self {
            MlKemSuite::MlKem512 => "ML-KEM-512 key pair",
            MlKemSuite::MlKem768 => "ML-KEM-768 key pair",
            MlKemSuite::MlKem1024 => "ML-KEM-1024 key pair",
        }
    }
    const fn key_pair_hash_kind(self) -> &'static str {
        match self {
            MlKemSuite::MlKem512 => "ML-KEM-512 key pair public hash",
            MlKemSuite::MlKem768 => "ML-KEM-768 key pair public hash",
            MlKemSuite::MlKem1024 => "ML-KEM-1024 key pair public hash",
        }
    }
    const fn secret_key_private_component_kind(self) -> &'static str {
        match self {
            MlKemSuite::MlKem512 => "ML-KEM-512 secret key private component",
            MlKemSuite::MlKem768 => "ML-KEM-768 secret key private component",
            MlKemSuite::MlKem1024 => "ML-KEM-1024 secret key private component",
        }
    }
    const fn secret_key_embedded_public_kind(self) -> &'static str {
        match self {
            MlKemSuite::MlKem512 => "ML-KEM-512 secret key embedded public key",
            MlKemSuite::MlKem768 => "ML-KEM-768 secret key embedded public key",
            MlKemSuite::MlKem1024 => "ML-KEM-1024 secret key embedded public key",
        }
    }
    const fn secret_key_implicit_rejection_seed_kind(self) -> &'static str {
        match self {
            MlKemSuite::MlKem512 => "ML-KEM-512 secret key implicit rejection seed",
            MlKemSuite::MlKem768 => "ML-KEM-768 secret key implicit rejection seed",
            MlKemSuite::MlKem1024 => "ML-KEM-1024 secret key implicit rejection seed",
        }
    }
    const fn secret_key_public_key_offset(self) -> usize {
        self.secret_key_public_key_hash_offset() - self.public_key_len()
    }
    const fn secret_key_public_key_hash_offset(self) -> usize {
        self.secret_key_len() - MLKEM_PUBLIC_KEY_HASH_BYTES - MLKEM_IMPLICIT_REJECTION_SEED_BYTES
    }
    const fn secret_key_implicit_rejection_seed_offset(self) -> usize {
        self.secret_key_len() - MLKEM_IMPLICIT_REJECTION_SEED_BYTES
    }
    fn validate_secret_key_len(self, bytes: &[u8]) -> Result<(), MlKemError> {
        validate_len(self.secret_key_kind(), bytes.len(), self.secret_key_len())
    }
    fn validate_key_material_not_all_zero(
        self,
        kind: &'static str,
        bytes: &[u8],
    ) -> Result<(), MlKemError> {
        if bytes.iter().all(|&byte| byte == 0) {
            return Err(MlKemError::InertKeyMaterial { suite: self, kind });
        }
        Ok(())
    }
    fn validate_secret_key_private_component(self, secret_key: &[u8]) -> Result<(), MlKemError> {
        self.validate_12_bit_coefficients(
            self.secret_key_private_component_kind(),
            self.secret_key_private_component_from_validated_secret_key(secret_key),
        )
    }
    fn validate_public_key_canonical(self, public_key: &[u8]) -> Result<(), MlKemError> {
        let polynomial_bytes = public_key
            .len()
            .checked_sub(MLKEM_PUBLIC_KEY_SEED_BYTES)
            .ok_or_else(|| {
                MlKemError::bad_encoding(
                    self.public_key_kind(),
                    PqError::BadLength {
                        name: self.public_key_kind(),
                        actual: public_key.len(),
                        expected: self.public_key_len(),
                    },
                )
            })?;
        self.validate_12_bit_coefficients(self.public_key_kind(), &public_key[..polynomial_bytes])
    }
    fn validate_12_bit_coefficients(
        self,
        kind: &'static str,
        bytes: &[u8],
    ) -> Result<(), MlKemError> {
        let chunks = bytes.chunks_exact(3);
        let remainder_len = chunks.remainder().len();
        if remainder_len != 0 {
            return Err(MlKemError::bad_encoding(
                kind,
                PqError::BadLength {
                    name: kind,
                    actual: bytes.len(),
                    expected: bytes
                        .len()
                        .checked_add(3 - remainder_len)
                        .unwrap_or(bytes.len()),
                },
            ));
        }
        for (pair_index, chunk) in chunks.enumerate() {
            let first = u16::from(chunk[0]) | (u16::from(chunk[1] & 0x0F) << 8);
            if first >= MLKEM_FIELD_MODULUS {
                return Err(MlKemError::NonCanonicalEncoding {
                    suite: self,
                    kind,
                    coefficient_index: pair_index * 2,
                    value: first,
                });
            }
            let second = (u16::from(chunk[1]) >> 4) | (u16::from(chunk[2]) << 4);
            if second >= MLKEM_FIELD_MODULUS {
                return Err(MlKemError::NonCanonicalEncoding {
                    suite: self,
                    kind,
                    coefficient_index: pair_index * 2 + 1,
                    value: second,
                });
            }
        }
        Ok(())
    }
    fn validate_secret_key_public_hash(self, secret_key: &[u8]) -> Result<(), MlKemError> {
        let embedded_public = self.public_key_from_validated_secret_key(secret_key);
        let embedded_public_hash = self.public_key_hash_from_validated_secret_key(secret_key);
        if embedded_public_hash != mlkem_public_key_hash(embedded_public).as_slice() {
            return Err(MlKemError::KeyPairPublicHashMismatch {
                suite: self,
                kind: self.key_pair_hash_kind(),
            });
        }
        Ok(())
    }
    fn secret_key_private_component_from_validated_secret_key(self, secret_key: &[u8]) -> &[u8] {
        &secret_key[..self.secret_key_public_key_offset()]
    }
    fn public_key_from_validated_secret_key(self, secret_key: &[u8]) -> &[u8] {
        let start = self.secret_key_public_key_offset();
        &secret_key[start..start + self.public_key_len()]
    }
    fn public_key_hash_from_validated_secret_key(self, secret_key: &[u8]) -> &[u8] {
        let start = self.secret_key_public_key_hash_offset();
        &secret_key[start..start + MLKEM_PUBLIC_KEY_HASH_BYTES]
    }
    fn implicit_rejection_seed_from_validated_secret_key(self, secret_key: &[u8]) -> &[u8] {
        let start = self.secret_key_implicit_rejection_seed_offset();
        &secret_key[start..start + MLKEM_IMPLICIT_REJECTION_SEED_BYTES]
    }
}
fn mlkem_public_key_hash(public_key: &[u8]) -> [u8; MLKEM_PUBLIC_KEY_HASH_BYTES] {
    let digest = Sha3_256::digest(public_key);
    let mut out = [0u8; MLKEM_PUBLIC_KEY_HASH_BYTES];
    out.copy_from_slice(&digest);
    out
}
/// Errors produced when parsing an [`MlKemSuite`] from text.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("unknown ML-KEM suite '{0}'")]
pub struct SuiteParseError(pub String);
impl fmt::Display for MlKemSuite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            MlKemSuite::MlKem512 => "mlkem512",
            MlKemSuite::MlKem768 => "mlkem768",
            MlKemSuite::MlKem1024 => "mlkem1024",
        })
    }
}
impl FromStr for MlKemSuite {
    type Err = SuiteParseError;
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input {
            "mlkem512" => Ok(MlKemSuite::MlKem512),
            "mlkem768" => Ok(MlKemSuite::MlKem768),
            "mlkem1024" => Ok(MlKemSuite::MlKem1024),
            _ => Err(SuiteParseError(input.to_string())),
        }
    }
}
/// Byte lengths for an ML-KEM suite.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MlKemParameters {
    /// Public key size in bytes.
    pub public_key: usize,
    /// Secret key size in bytes.
    pub secret_key: usize,
    /// Ciphertext size in bytes.
    pub ciphertext: usize,
    /// Shared secret size in bytes.
    pub shared_secret: usize,
}
impl From<MlKemSuite> for MlKemParameters {
    fn from(suite: MlKemSuite) -> Self {
        suite.parameters()
    }
}
/// Detailed metadata for an ML-KEM suite as specified in FIPS 203.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MlKemMetadata {
    /// Suite identifier (`MlKemSuite`) this metadata describes.
    pub suite: MlKemSuite,
    /// Human-readable ML-KEM suite name.
    pub name: &'static str,
    /// Canonical `SoraNet` capability identifier (`snnet.pqkem` `kem_id`).
    pub kem_id: u8,
    /// NIST security strength category (1, 3, or 5).
    pub security_category: u8,
    /// Target symmetric security in bits (e.g., 128, 192, 256).
    pub symmetric_security_bits: u16,
    /// Degree of the module lattice polynomial (`n`).
    pub module_degree: u16,
    /// Rank of the module (`k` parameter from FIPS 203).
    pub module_rank: u8,
    /// Modulus `q` for the ring `Z_q[x]/(x^n + 1)`.
    pub modulus_q: u16,
    /// Noise parameter `η₁` used when sampling secret polynomials.
    pub eta1: u8,
    /// Noise parameter `η₂` used during reconciliation.
    pub eta2: u8,
    /// Compression parameter `d_u` applied to the public key.
    pub du: u8,
    /// Compression parameter `d_v` applied to the ciphertext.
    pub dv: u8,
    /// Byte lengths for the suite.
    pub parameters: MlKemParameters,
}
impl MlKemSuite {
    /// Return the metadata record describing this suite.
    #[must_use]
    pub const fn metadata(self) -> MlKemMetadata {
        match self {
            MlKemSuite::MlKem512 => MlKemMetadata {
                suite: MlKemSuite::MlKem512,
                name: "ML-KEM-512",
                kem_id: 0,
                security_category: 1,
                symmetric_security_bits: 128,
                module_degree: 256,
                module_rank: 2,
                modulus_q: 3329,
                eta1: 3,
                eta2: 2,
                du: 10,
                dv: 4,
                parameters: MlKemParameters {
                    public_key: 800,
                    secret_key: 1632,
                    ciphertext: 768,
                    shared_secret: 32,
                },
            },
            MlKemSuite::MlKem768 => MlKemMetadata {
                suite: MlKemSuite::MlKem768,
                name: "ML-KEM-768",
                kem_id: 1,
                security_category: 3,
                symmetric_security_bits: 192,
                module_degree: 256,
                module_rank: 3,
                modulus_q: 3329,
                eta1: 2,
                eta2: 2,
                du: 10,
                dv: 4,
                parameters: MlKemParameters {
                    public_key: 1184,
                    secret_key: 2400,
                    ciphertext: 1088,
                    shared_secret: 32,
                },
            },
            MlKemSuite::MlKem1024 => MlKemMetadata {
                suite: MlKemSuite::MlKem1024,
                name: "ML-KEM-1024",
                kem_id: 2,
                security_category: 5,
                symmetric_security_bits: 256,
                module_degree: 256,
                module_rank: 4,
                modulus_q: 3329,
                eta1: 2,
                eta2: 2,
                du: 11,
                dv: 5,
                parameters: MlKemParameters {
                    public_key: 1568,
                    secret_key: 3168,
                    ciphertext: 1568,
                    shared_secret: 32,
                },
            },
        }
    }
}
/// Wrapper around an ML-KEM keypair (public + secret).
pub struct MlKemKeyPair {
    /// Public key bytes.
    pub public_key: Vec<u8>,
    /// Secret key bytes, zeroized on drop.
    pub secret_key: Zeroizing<Vec<u8>>,
}
impl fmt::Debug for MlKemKeyPair {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MlKemKeyPair")
            .field("public_key_len", &self.public_key.len())
            .field("secret_key", &"[REDACTED]")
            .finish()
    }
}
impl MlKemKeyPair {
    /// Return the public key as raw bytes.
    #[must_use]
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }
    /// Return the secret key as raw bytes.
    #[must_use]
    pub fn secret_key(&self) -> &[u8] {
        &self.secret_key
    }
}
/// Encapsulated ML-KEM ciphertext.
#[derive(Debug, Clone)]
pub struct MlKemCiphertext {
    bytes: Vec<u8>,
}
impl MlKemCiphertext {
    /// Construct from raw ciphertext bytes.
    #[cfg(test)]
    fn try_new(suite: MlKemSuite, bytes: Vec<u8>) -> Result<Self, MlKemError> {
        suite.validate_ciphertext(&bytes)?;
        Ok(Self { bytes })
    }
    /// Access the ciphertext bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}
/// Shared secret output of an ML-KEM operation.
pub struct MlKemSharedSecret {
    bytes: Zeroizing<Vec<u8>>,
}
impl fmt::Debug for MlKemSharedSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MlKemSharedSecret")
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}
impl MlKemSharedSecret {
    #[cfg(test)]
    fn try_new(suite: MlKemSuite, bytes: Zeroizing<Vec<u8>>) -> Result<Self, MlKemError> {
        validate_len(
            suite.shared_secret_kind(),
            bytes.len(),
            suite.shared_secret_len(),
        )?;
        suite.validate_key_material_not_all_zero(suite.shared_secret_kind(), bytes.as_slice())?;
        Ok(Self { bytes })
    }
    /// Access the shared secret bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}
/// Errors that can arise while working with ML-KEM wrappers.
#[derive(Clone, Debug, Error)]
pub enum MlKemError {
    /// Input byte string had an unexpected length.
    #[error("invalid {kind} encoding: {source}")]
    BadEncoding {
        /// Identifier of the field that failed to decode.
        kind: &'static str,
        /// Original `PQClean` error.
        #[source]
        source: Box<PqError>,
    },
    /// Public key and secret key encodings were individually well-formed but not paired.
    #[error("{suite} public key does not match secret key")]
    KeyPairMismatch {
        /// ML-KEM parameter set being validated.
        suite: MlKemSuite,
        /// Identifier of the key-pair material that failed to match.
        kind: &'static str,
    },
    /// Secret key embeds the expected public key but an inconsistent `H(ek)` hash.
    #[error("{suite} secret key public hash does not match public key")]
    KeyPairPublicHashMismatch {
        /// ML-KEM parameter set being validated.
        suite: MlKemSuite,
        /// Identifier of the key-pair material that failed to match.
        kind: &'static str,
    },
    /// Encoded field elements are outside the canonical ML-KEM range.
    #[error("{suite} {kind} is not canonical: coefficient {coefficient_index} has value {value}")]
    NonCanonicalEncoding {
        /// ML-KEM parameter set being validated.
        suite: MlKemSuite,
        /// Identifier of the key material that failed to decode canonically.
        kind: &'static str,
        /// Zero-based coefficient index in the decoded polynomial vector.
        coefficient_index: usize,
        /// Rejected 12-bit value.
        value: u16,
    },
    /// Key material was an inert all-zero placeholder.
    #[error("{suite} {kind} must not be all zero")]
    InertKeyMaterial {
        /// ML-KEM parameter set being validated.
        suite: MlKemSuite,
        /// Identifier of the key material that was all zero.
        kind: &'static str,
    },
    /// The ML-KEM backend returned a nonzero status for an operation.
    #[error("{suite} backend {operation} failed with status {status}")]
    BackendFailure {
        /// ML-KEM parameter set being used.
        suite: MlKemSuite,
        /// Backend operation name.
        operation: &'static str,
        /// Nonzero backend status code.
        status: i32,
    },
    /// Hedged RNG seed construction failed.
    #[error(transparent)]
    Rng(#[from] RngError),
}
impl MlKemError {
    fn bad_encoding(kind: &'static str, source: PqError) -> Self {
        MlKemError::BadEncoding {
            kind,
            source: Box::new(source),
        }
    }
}
fn validate_len(kind: &'static str, actual: usize, expected: usize) -> Result<(), MlKemError> {
    if actual == expected {
        Ok(())
    } else {
        Err(MlKemError::bad_encoding(
            kind,
            PqError::BadLength {
                name: kind,
                actual,
                expected,
            },
        ))
    }
}
fn validate_mlkem_seed_material_not_all_zero(
    suite: MlKemSuite,
    seed: &HedgedRngSeed,
) -> Result<(), MlKemError> {
    if seed.is_all_zero() {
        return Err(MlKemError::InertKeyMaterial {
            suite,
            kind: "ML-KEM seed material",
        });
    }
    Ok(())
}
fn mlkem_backend_status(
    suite: MlKemSuite,
    operation: &'static str,
    status: i32,
) -> Result<(), MlKemError> {
    if status == 0 {
        Ok(())
    } else {
        Err(MlKemError::BackendFailure {
            suite,
            operation,
            status,
        })
    }
}
/// Generate an ML-KEM keypair for the given parameter set.
///
/// # Errors
/// Returns an error when generated key material fails ML-KEM key-pair
/// validation or the backend reports key-generation failure.
pub fn generate_mlkem_keypair(
    suite: MlKemSuite,
    rng: &mut HedgedChaCha20Rng,
) -> Result<MlKemKeyPair, MlKemError> {
    let mut coins = Zeroizing::new([0u8; 64]);
    rng.fill_bytes(coins.as_mut());
    generate_mlkem_keypair_from_coins(suite, &coins)
}
/// Generate into initialized, exact-suite caller storage without allocating output backing.
///
/// Secret output is erased on every error or unwind. On success the caller owns
/// its erasure duty and should retain the buffer in `Zeroizing` storage. Public
/// output is not usable until this operation succeeds.
///
/// # Errors
/// Returns the existing geometry, generated-material or backend error. Output
/// geometry is checked before consuming randomness or invoking the backend.
pub fn generate_mlkem_keypair_into(
    suite: MlKemSuite,
    rng: &mut HedgedChaCha20Rng,
    public_key: &mut [u8],
    secret_key: &mut [u8],
) -> Result<(), MlKemError> {
    let mut secret = SecretOutput::new(secret_key);
    validate_len(
        suite.public_key_kind(),
        public_key.len(),
        suite.public_key_len(),
    )?;
    validate_len(
        suite.secret_key_kind(),
        secret.bytes.len(),
        suite.secret_key_len(),
    )?;
    let mut coins = Zeroizing::new([0u8; 64]);
    rng.fill_bytes(coins.as_mut());
    generate_mlkem_keypair_from_coins_into(suite, &coins, public_key, secret.bytes)?;
    secret.complete();
    Ok(())
}

// Only successful callers may retain generated secret material. This guard has
// no allocation and also erases output when validation or the backend unwinds.
struct SecretOutput<'a> {
    bytes: &'a mut [u8],
    complete: bool,
}
impl<'a> SecretOutput<'a> {
    fn new(bytes: &'a mut [u8]) -> Self {
        Self {
            bytes,
            complete: false,
        }
    }
    fn complete(&mut self) {
        self.complete = true;
    }
}
impl Drop for SecretOutput<'_> {
    fn drop(&mut self) {
        if !self.complete {
            self.bytes.zeroize();
        }
    }
}

fn generate_mlkem_keypair_from_coins_into(
    suite: MlKemSuite,
    coins: &[u8; 64],
    public_key: &mut [u8],
    secret_key: &mut [u8],
) -> Result<(), MlKemError> {
    let mut secret = SecretOutput::new(secret_key);
    suite.validate_key_material_not_all_zero("ML-KEM keypair coins", coins)?;
    validate_len(
        suite.public_key_kind(),
        public_key.len(),
        suite.public_key_len(),
    )?;
    validate_len(
        suite.secret_key_kind(),
        secret.bytes.len(),
        suite.secret_key_len(),
    )?;
    mlkem_ffi::keypair_derand(suite, public_key, secret.bytes, coins)?;
    suite.validate_key_pair(public_key, secret.bytes)?;
    secret.complete();
    Ok(())
}

/// Generate an ML-KEM keypair using a seed plus live OS entropy when available.
///
/// # Errors
/// Returns [`MlKemError::Rng`] when the initial OS seed draw fails, or another ML-KEM error when
/// generated material fails validation or the backend reports key-generation failure.
pub fn generate_mlkem_keypair_from_os(suite: MlKemSuite) -> Result<MlKemKeyPair, MlKemError> {
    let mut rng = rand::rngs::OsRng;
    generate_mlkem_keypair_from_rng(suite, &mut rng)
}
/// Generate an ML-KEM keypair using caller-supplied seed entropy plus live OS
/// entropy when available.
///
/// # Errors
/// Returns [`MlKemError::Rng`] when the required seed draw fails, or another ML-KEM error when
/// generated material fails validation or the backend reports key-generation failure.
pub fn generate_mlkem_keypair_from_rng<R: TryCryptoRng + ?Sized>(
    suite: MlKemSuite,
    rng: &mut R,
) -> Result<MlKemKeyPair, MlKemError> {
    let mut rng = hedged_chacha20_rng_from_rng(b"soranet-pq:mlkem:keypair", rng)?;
    generate_mlkem_keypair(suite, &mut rng)
}
/// Deterministically generate an ML-KEM keypair from explicit seed material.
///
/// # Errors
/// Returns an error when seed material is all zero, generated key material fails ML-KEM key-pair
/// validation, or the backend reports key-generation failure.
pub fn generate_mlkem_keypair_from_seed(
    suite: MlKemSuite,
    seed: HedgedRngSeed,
    personalization: &[u8],
) -> Result<MlKemKeyPair, MlKemError> {
    validate_mlkem_seed_material_not_all_zero(suite, &seed)?;
    let mut rng = deterministic_chacha20_rng(seed, personalization);
    generate_mlkem_keypair(suite, &mut rng)
}
fn generate_mlkem_keypair_from_coins(
    suite: MlKemSuite,
    coins: &[u8; 64],
) -> Result<MlKemKeyPair, MlKemError> {
    suite.validate_key_material_not_all_zero("ML-KEM keypair coins", coins)?;
    let mut public_key = vec![0u8; suite.public_key_len()];
    let mut secret_key = Zeroizing::new(vec![0u8; suite.secret_key_len()]);
    generate_mlkem_keypair_from_coins_into(suite, coins, &mut public_key, secret_key.as_mut())?;
    let keypair = MlKemKeyPair {
        public_key,
        secret_key,
    };
    Ok(keypair)
}
#[cfg(test)]
fn validate_generated_mlkem_keypair(
    suite: MlKemSuite,
    keypair: &MlKemKeyPair,
) -> Result<(), MlKemError> {
    validate_mlkem_key_pair(suite, keypair.public_key(), keypair.secret_key())
}
/// Encapsulate against a provided public key.
///
/// # Errors
/// Returns an error when the public key length is invalid or its field coefficients are
/// noncanonical, or when the backend reports encapsulation failure.
pub fn encapsulate_mlkem(
    suite: MlKemSuite,
    public_key: &[u8],
    rng: &mut HedgedChaCha20Rng,
) -> Result<(MlKemSharedSecret, MlKemCiphertext), MlKemError> {
    suite.validate_public_key(public_key)?;
    let mut coins = Zeroizing::new([0u8; 32]);
    rng.fill_bytes(coins.as_mut());
    encapsulate_mlkem_from_coins(suite, public_key, &coins)
}
/// Encapsulate into initialized, exact-suite shared-secret and ciphertext buffers.
///
/// The public-key checks precede output geometry and RNG use. Secret output is
/// erased on error or unwind; successful callers must retain zeroizing custody.
/// Ciphertext is usable only on success.
///
/// # Errors
/// Returns the existing input/output geometry, canonical-material or backend error.
pub fn encapsulate_mlkem_into(
    suite: MlKemSuite,
    public_key: &[u8],
    rng: &mut HedgedChaCha20Rng,
    shared_secret: &mut [u8],
    ciphertext: &mut [u8],
) -> Result<(), MlKemError> {
    let mut shared = SecretOutput::new(shared_secret);
    suite.validate_public_key(public_key)?;
    validate_len(
        suite.shared_secret_kind(),
        shared.bytes.len(),
        suite.shared_secret_len(),
    )?;
    validate_len(
        suite.ciphertext_kind(),
        ciphertext.len(),
        suite.ciphertext_len(),
    )?;
    let mut coins = Zeroizing::new([0u8; 32]);
    rng.fill_bytes(coins.as_mut());
    encapsulate_mlkem_from_coins_into(suite, public_key, &coins, shared.bytes, ciphertext)?;
    shared.complete();
    Ok(())
}

fn encapsulate_mlkem_from_coins_into(
    suite: MlKemSuite,
    public_key: &[u8],
    coins: &[u8; 32],
    shared_secret: &mut [u8],
    ciphertext: &mut [u8],
) -> Result<(), MlKemError> {
    let mut shared = SecretOutput::new(shared_secret);
    suite.validate_public_key(public_key)?;
    suite.validate_key_material_not_all_zero("ML-KEM encapsulation coins", coins)?;
    validate_len(
        suite.shared_secret_kind(),
        shared.bytes.len(),
        suite.shared_secret_len(),
    )?;
    validate_len(
        suite.ciphertext_kind(),
        ciphertext.len(),
        suite.ciphertext_len(),
    )?;
    mlkem_ffi::encapsulate_derand(suite, ciphertext, shared.bytes, public_key, coins)?;
    suite.validate_key_material_not_all_zero(suite.shared_secret_kind(), shared.bytes)?;
    suite.validate_ciphertext(ciphertext)?;
    shared.complete();
    Ok(())
}

/// Encapsulate using seed material plus live OS entropy when available.
///
/// # Errors
/// Returns [`MlKemError::Rng`] when the initial OS seed draw fails, or [`MlKemError::BadEncoding`]
/// or [`MlKemError::NonCanonicalEncoding`] when the public key encoding is invalid, or
/// [`MlKemError::BackendFailure`] when the backend reports encapsulation failure.
pub fn encapsulate_mlkem_from_os(
    suite: MlKemSuite,
    public_key: &[u8],
) -> Result<(MlKemSharedSecret, MlKemCiphertext), MlKemError> {
    let mut rng = rand::rngs::OsRng;
    encapsulate_mlkem_from_rng(suite, public_key, &mut rng)
}
/// Encapsulate using caller-supplied seed entropy plus live OS entropy when available.
///
/// # Errors
/// Returns [`MlKemError::Rng`] when the required seed draw fails, or [`MlKemError::BadEncoding`] or
/// [`MlKemError::NonCanonicalEncoding`] when the public key encoding is invalid, or
/// [`MlKemError::BackendFailure`] when the backend reports encapsulation failure.
pub fn encapsulate_mlkem_from_rng<R: TryCryptoRng + ?Sized>(
    suite: MlKemSuite,
    public_key: &[u8],
    rng: &mut R,
) -> Result<(MlKemSharedSecret, MlKemCiphertext), MlKemError> {
    suite.validate_public_key(public_key)?;
    let mut rng = hedged_chacha20_rng_from_rng(b"soranet-pq:mlkem:encapsulate", rng)?;
    encapsulate_mlkem(suite, public_key, &mut rng)
}
/// Deterministically encapsulate from explicit seed material.
///
/// # Errors
/// Returns an error when the public key length is invalid, its field coefficients are noncanonical,
/// the seed material is all zero, or when the backend reports encapsulation failure.
pub fn encapsulate_mlkem_from_seed(
    suite: MlKemSuite,
    public_key: &[u8],
    seed: HedgedRngSeed,
    personalization: &[u8],
) -> Result<(MlKemSharedSecret, MlKemCiphertext), MlKemError> {
    suite.validate_public_key(public_key)?;
    validate_mlkem_seed_material_not_all_zero(suite, &seed)?;
    let mut rng = deterministic_chacha20_rng(seed, personalization);
    encapsulate_mlkem(suite, public_key, &mut rng)
}
fn encapsulate_mlkem_from_coins(
    suite: MlKemSuite,
    public_key: &[u8],
    coins: &[u8; 32],
) -> Result<(MlKemSharedSecret, MlKemCiphertext), MlKemError> {
    suite.validate_public_key(public_key)?;
    suite.validate_key_material_not_all_zero("ML-KEM encapsulation coins", coins)?;
    let mut shared = Zeroizing::new(vec![0u8; suite.shared_secret_len()]);
    let mut ciphertext = vec![0u8; suite.ciphertext_len()];
    encapsulate_mlkem_from_coins_into(suite, public_key, coins, shared.as_mut(), &mut ciphertext)?;
    Ok((
        MlKemSharedSecret { bytes: shared },
        MlKemCiphertext { bytes: ciphertext },
    ))
}
/// Decapsulate a ciphertext with the provided secret key.
///
/// # Errors
/// Returns an error when the secret key, embedded public key, or ciphertext encoding is invalid or
/// inert, or when the backend reports decapsulation failure.
pub fn decapsulate_mlkem(
    suite: MlKemSuite,
    secret_key: &[u8],
    ciphertext: &[u8],
) -> Result<MlKemSharedSecret, MlKemError> {
    suite.validate_secret_key(secret_key)?;
    suite.validate_ciphertext(ciphertext)?;
    let mut shared = Zeroizing::new(vec![0u8; suite.shared_secret_len()]);
    decapsulate_mlkem_into(suite, secret_key, ciphertext, shared.as_mut())?;
    Ok(MlKemSharedSecret { bytes: shared })
}
/// Decapsulate into initialized, exact-suite shared-secret storage.
///
/// Secret-key validation precedes ciphertext validation, followed by output
/// geometry. Output is erased on any error or unwind; successful callers must
/// retain it in zeroizing custody.
///
/// # Errors
/// Returns the existing input/output geometry, canonical-material or backend error.
pub fn decapsulate_mlkem_into(
    suite: MlKemSuite,
    secret_key: &[u8],
    ciphertext: &[u8],
    shared_secret: &mut [u8],
) -> Result<(), MlKemError> {
    let mut shared = SecretOutput::new(shared_secret);
    suite.validate_secret_key(secret_key)?;
    suite.validate_ciphertext(ciphertext)?;
    validate_len(
        suite.shared_secret_kind(),
        shared.bytes.len(),
        suite.shared_secret_len(),
    )?;
    mlkem_ffi::decapsulate(suite, shared.bytes, ciphertext, secret_key)?;
    suite.validate_key_material_not_all_zero(suite.shared_secret_kind(), shared.bytes)?;
    shared.complete();
    Ok(())
}

/// Return parameter lengths for the given ML-KEM suite.
#[must_use]
pub fn mlkem_parameters(suite: MlKemSuite) -> MlKemParameters {
    suite.metadata().parameters
}
/// Return the metadata record for the provided ML-KEM suite.
#[must_use]
pub fn mlkem_metadata(suite: MlKemSuite) -> MlKemMetadata {
    suite.metadata()
}
/// Validate the encoding of an ML-KEM public key.
///
/// # Errors
/// Returns an error when the public key length is invalid or its field
/// coefficients are noncanonical.
pub fn validate_mlkem_public_key(suite: MlKemSuite, bytes: &[u8]) -> Result<(), MlKemError> {
    suite.validate_public_key(bytes)
}
/// Validate the encoding of an ML-KEM secret key.
///
/// # Errors
/// Returns an error when the secret key length is invalid, its private component or embedded public
/// key is noncanonical, or its embedded public-key hash is inconsistent.
pub fn validate_mlkem_secret_key(suite: MlKemSuite, bytes: &[u8]) -> Result<(), MlKemError> {
    suite.validate_secret_key(bytes)
}
/// Validate the encoding of an ML-KEM ciphertext.
///
/// # Errors
/// Returns an error when the ciphertext has the wrong length or is inert all-zero material.
pub fn validate_mlkem_ciphertext(suite: MlKemSuite, bytes: &[u8]) -> Result<(), MlKemError> {
    suite.validate_ciphertext(bytes)
}
/// Validate that public and secret ML-KEM keys belong to the same key pair.
///
/// # Errors
/// Returns [`MlKemError::BadEncoding`] for malformed lengths and
/// [`MlKemError::NonCanonicalEncoding`] for noncanonical public-key field coefficients,
/// [`MlKemError::KeyPairMismatch`] when the keys are individually well-formed but not paired, or
/// [`MlKemError::KeyPairPublicHashMismatch`] when the secret key's embedded `H(ek)` value does not
/// match its embedded public key.
pub fn validate_mlkem_key_pair(
    suite: MlKemSuite,
    public_key: &[u8],
    secret_key: &[u8],
) -> Result<(), MlKemError> {
    suite.validate_key_pair(public_key, secret_key)
}
#[allow(unsafe_code)]
mod mlkem_ffi {
    use super::{MlKemError, MlKemSuite, mlkem_backend_status};
    use core::ffi::c_int;
    pub fn keypair_derand(
        suite: MlKemSuite,
        public_key: &mut [u8],
        secret_key: &mut [u8],
        coins: &[u8; 64],
    ) -> Result<(), MlKemError> {
        let status = unsafe {
            match suite {
                MlKemSuite::MlKem512 => PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair_derand(
                    public_key.as_mut_ptr(),
                    secret_key.as_mut_ptr(),
                    coins.as_ptr(),
                ),
                MlKemSuite::MlKem768 => PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair_derand(
                    public_key.as_mut_ptr(),
                    secret_key.as_mut_ptr(),
                    coins.as_ptr(),
                ),
                MlKemSuite::MlKem1024 => PQCLEAN_MLKEM1024_CLEAN_crypto_kem_keypair_derand(
                    public_key.as_mut_ptr(),
                    secret_key.as_mut_ptr(),
                    coins.as_ptr(),
                ),
            }
        };
        mlkem_backend_status(suite, "derandomized keygen", status)
    }
    pub fn encapsulate_derand(
        suite: MlKemSuite,
        ciphertext: &mut [u8],
        shared_secret: &mut [u8],
        public_key: &[u8],
        coins: &[u8; 32],
    ) -> Result<(), MlKemError> {
        let status = unsafe {
            match suite {
                MlKemSuite::MlKem512 => PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc_derand(
                    ciphertext.as_mut_ptr(),
                    shared_secret.as_mut_ptr(),
                    public_key.as_ptr(),
                    coins.as_ptr(),
                ),
                MlKemSuite::MlKem768 => PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc_derand(
                    ciphertext.as_mut_ptr(),
                    shared_secret.as_mut_ptr(),
                    public_key.as_ptr(),
                    coins.as_ptr(),
                ),
                MlKemSuite::MlKem1024 => PQCLEAN_MLKEM1024_CLEAN_crypto_kem_enc_derand(
                    ciphertext.as_mut_ptr(),
                    shared_secret.as_mut_ptr(),
                    public_key.as_ptr(),
                    coins.as_ptr(),
                ),
            }
        };
        mlkem_backend_status(suite, "derandomized encapsulation", status)
    }
    pub fn decapsulate(
        suite: MlKemSuite,
        shared_secret: &mut [u8],
        ciphertext: &[u8],
        secret_key: &[u8],
    ) -> Result<(), MlKemError> {
        let status = unsafe {
            match suite {
                MlKemSuite::MlKem512 => PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(
                    shared_secret.as_mut_ptr(),
                    ciphertext.as_ptr(),
                    secret_key.as_ptr(),
                ),
                MlKemSuite::MlKem768 => PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(
                    shared_secret.as_mut_ptr(),
                    ciphertext.as_ptr(),
                    secret_key.as_ptr(),
                ),
                MlKemSuite::MlKem1024 => PQCLEAN_MLKEM1024_CLEAN_crypto_kem_dec(
                    shared_secret.as_mut_ptr(),
                    ciphertext.as_ptr(),
                    secret_key.as_ptr(),
                ),
            }
        };
        mlkem_backend_status(suite, "decapsulation", status)
    }
    unsafe extern "C" {
        fn PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair_derand(
            pk: *mut u8,
            sk: *mut u8,
            coins: *const u8,
        ) -> c_int;
        fn PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc_derand(
            ct: *mut u8,
            ss: *mut u8,
            pk: *const u8,
            coins: *const u8,
        ) -> c_int;
        fn PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(
            ss: *mut u8,
            ct: *const u8,
            sk: *const u8,
        ) -> c_int;
        fn PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair_derand(
            pk: *mut u8,
            sk: *mut u8,
            coins: *const u8,
        ) -> c_int;
        fn PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc_derand(
            ct: *mut u8,
            ss: *mut u8,
            pk: *const u8,
            coins: *const u8,
        ) -> c_int;
        fn PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(
            ss: *mut u8,
            ct: *const u8,
            sk: *const u8,
        ) -> c_int;
        fn PQCLEAN_MLKEM1024_CLEAN_crypto_kem_keypair_derand(
            pk: *mut u8,
            sk: *mut u8,
            coins: *const u8,
        ) -> c_int;
        fn PQCLEAN_MLKEM1024_CLEAN_crypto_kem_enc_derand(
            ct: *mut u8,
            ss: *mut u8,
            pk: *const u8,
            coins: *const u8,
        ) -> c_int;
        fn PQCLEAN_MLKEM1024_CLEAN_crypto_kem_dec(
            ss: *mut u8,
            ct: *const u8,
            sk: *const u8,
        ) -> c_int;
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{deterministic_chacha20_rng, hedged_chacha20_rng};
    use rand_core::{TryCryptoRng, TryRngCore};
    #[derive(Debug)]
    struct FailingPqSeedRng;
    #[derive(Debug)]
    struct FailingPqSeedRngError;
    impl core::fmt::Display for FailingPqSeedRngError {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str("failing ML-KEM seed RNG")
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
    fn set_first_12_bit_coefficient_noncanonical(bytes: &mut [u8]) {
        bytes[0] = 0xFF;
        bytes[1] = (bytes[1] & 0xF0) | 0x0F;
    }
    fn set_first_public_key_coefficient_noncanonical(public_key: &mut [u8]) {
        set_first_12_bit_coefficient_noncanonical(public_key);
    }
    fn assert_noncanonical_encoding(
        err: MlKemError,
        suite: MlKemSuite,
        expected_kind_fragment: &str,
    ) {
        match err {
            MlKemError::NonCanonicalEncoding {
                suite: found_suite,
                kind,
                coefficient_index: 0,
                value,
            } => {
                assert_eq!(found_suite, suite);
                assert!(kind.contains(expected_kind_fragment));
                assert!(value >= MLKEM_FIELD_MODULUS);
            }
            other => panic!("expected noncanonical {expected_kind_fragment} error, got {other:?}"),
        }
    }
    fn assert_noncanonical_public_key(err: MlKemError, suite: MlKemSuite) {
        assert_noncanonical_encoding(err, suite, "public key");
    }
    fn assert_inert_key_material(err: MlKemError, suite: MlKemSuite, expected_kind_fragment: &str) {
        match err {
            MlKemError::InertKeyMaterial {
                suite: found_suite,
                kind,
            } => {
                assert_eq!(found_suite, suite);
                assert!(
                    kind.contains(expected_kind_fragment),
                    "expected {kind:?} to mention {expected_kind_fragment:?}"
                );
            }
            other => panic!("expected inert {expected_kind_fragment} error, got {other:?}"),
        }
    }
    #[test]
    fn coefficient_validation_rejects_partial_12_bit_group() {
        let suite = MlKemSuite::MlKem512;
        let err = suite
            .validate_12_bit_coefficients(suite.public_key_kind(), &[0xAA, 0xBB])
            .expect_err("partial 12-bit coefficient group must fail validation");
        match err {
            MlKemError::BadEncoding { kind, source } => {
                assert!(kind.contains("public key"));
                match *source {
                    PqError::BadLength {
                        name,
                        actual,
                        expected,
                    } => {
                        assert_eq!(name, kind);
                        assert_eq!(actual, 2);
                        assert_eq!(expected, 3);
                    }
                    other => panic!("unexpected partial-group error: {other:?}"),
                }
            }
            other => panic!("unexpected partial-group validation result: {other:?}"),
        }
    }
    #[test]
    fn backend_status_reports_nonzero_failures() {
        mlkem_backend_status(MlKemSuite::MlKem768, "test operation", 0)
            .expect("zero status succeeds");
        let err = mlkem_backend_status(MlKemSuite::MlKem768, "test operation", 7)
            .expect_err("nonzero status fails");
        match err {
            MlKemError::BackendFailure {
                suite,
                operation,
                status,
            } => {
                assert_eq!(suite, MlKemSuite::MlKem768);
                assert_eq!(operation, "test operation");
                assert_eq!(status, 7);
            }
            other => panic!("unexpected backend status error: {other:?}"),
        }
    }
    #[test]
    fn ciphertext_constructor_preserves_guarded_payload() {
        let suite = MlKemSuite::MlKem768;
        let expected = vec![0xA7; suite.ciphertext_len()];
        let ciphertext =
            MlKemCiphertext::try_new(suite, expected.clone()).expect("ML-KEM ciphertext");
        assert_eq!(ciphertext.as_bytes(), expected.as_slice());
    }
    #[test]
    fn ciphertext_constructor_rejects_all_zero_payload() {
        let suite = MlKemSuite::MlKem768;
        let err = MlKemCiphertext::try_new(suite, vec![0u8; suite.ciphertext_len()])
            .expect_err("all-zero ML-KEM ciphertext must be rejected");
        assert_inert_key_material(err, suite, "ciphertext");
    }
    #[test]
    fn shared_secret_constructor_preserves_guarded_payload() {
        let expected = vec![0xA7; MlKemSuite::MlKem768.shared_secret_len()];
        let secret =
            MlKemSharedSecret::try_new(MlKemSuite::MlKem768, Zeroizing::new(expected.clone()))
                .expect("nonzero ML-KEM shared secret should be accepted");
        assert_eq!(secret.as_bytes(), expected.as_slice());
    }
    #[test]
    fn secret_bearing_debug_output_is_redacted() {
        let keypair = MlKemKeyPair {
            public_key: vec![0x11; 2],
            secret_key: Zeroizing::new(vec![0xA5; 3]),
        };
        assert_eq!(
            format!("{keypair:?}"),
            "MlKemKeyPair { public_key_len: 2, secret_key: \"[REDACTED]\" }"
        );

        let secret = MlKemSharedSecret::try_new(
            MlKemSuite::MlKem768,
            Zeroizing::new(vec![0xA5; MlKemSuite::MlKem768.shared_secret_len()]),
        )
        .expect("nonzero shared secret");
        assert_eq!(
            format!("{secret:?}"),
            "MlKemSharedSecret { bytes: \"[REDACTED]\" }"
        );
    }
    #[test]
    fn shared_secret_constructor_rejects_all_zero_payload() {
        let suite = MlKemSuite::MlKem768;
        let err =
            MlKemSharedSecret::try_new(suite, Zeroizing::new(vec![0u8; suite.shared_secret_len()]))
                .expect_err("all-zero ML-KEM shared secret must be rejected");
        assert_inert_key_material(err, suite, "shared secret");
    }
    fn roundtrip(suite: MlKemSuite) {
        let mut rng = hedged_chacha20_rng(
            HedgedRngSeed::from_entropy([suite.kem_id(); 32]),
            b"mlkem-test-keypair",
        );
        let mut enc_rng = hedged_chacha20_rng(
            HedgedRngSeed::from_entropy([suite.kem_id().wrapping_add(1); 32]),
            b"mlkem-test-encap",
        );
        let keys = generate_mlkem_keypair(suite, &mut rng).expect("generated keypair validates");
        let (shared_a, ct) = encapsulate_mlkem(suite, keys.public_key(), &mut enc_rng).unwrap();
        let shared_b = decapsulate_mlkem(suite, keys.secret_key(), ct.as_bytes()).unwrap();
        assert_eq!(shared_a.as_bytes(), shared_b.as_bytes());
    }
    #[test]
    fn roundtrip_512() {
        roundtrip(MlKemSuite::MlKem512);
    }
    #[test]
    fn roundtrip_768() {
        roundtrip(MlKemSuite::MlKem768);
    }
    #[test]
    fn roundtrip_1024() {
        roundtrip(MlKemSuite::MlKem1024);
    }
    #[test]
    fn from_os_helpers_roundtrip() {
        let suite = MlKemSuite::MlKem512;
        let keypair =
            generate_mlkem_keypair_from_os(suite).expect("OS-backed ML-KEM keypair generation");
        let (sender_shared, ciphertext) = encapsulate_mlkem_from_os(suite, keypair.public_key())
            .expect("OS-backed ML-KEM encapsulation");
        let receiver_shared = decapsulate_mlkem(suite, keypair.secret_key(), ciphertext.as_bytes())
            .expect("ML-KEM decapsulation");
        assert_eq!(sender_shared.as_bytes(), receiver_shared.as_bytes());
    }
    #[test]
    fn from_rng_keypair_reports_seed_failure() {
        let mut rng = FailingPqSeedRng;
        match generate_mlkem_keypair_from_rng(MlKemSuite::MlKem512, &mut rng) {
            Err(MlKemError::Rng(RngError)) => {}
            Ok(_) => panic!("ML-KEM keypair seed RNG failure must be reported"),
            Err(other) => panic!("expected ML-KEM RNG error, got {other:?}"),
        }
    }
    #[test]
    fn from_rng_keypair_rejects_all_zero_seed_material() {
        let mut rng = FixedPqSeedRng { seed: [0_u8; 32] };
        match generate_mlkem_keypair_from_rng(MlKemSuite::MlKem512, &mut rng) {
            Err(MlKemError::Rng(RngError)) => {}
            Ok(_) => panic!("ML-KEM keypair all-zero seed material must be rejected"),
            Err(other) => panic!("expected ML-KEM inert seed RNG error, got {other:?}"),
        }
    }
    #[test]
    fn from_rng_encapsulation_reports_seed_failure() {
        let suite = MlKemSuite::MlKem512;
        let keypair = generate_mlkem_keypair_from_seed(
            suite,
            HedgedRngSeed::from_entropy([0xA6; 32]),
            b"failing-encap-keygen",
        )
        .expect("seeded ML-KEM keypair generation should succeed");
        let mut rng = FailingPqSeedRng;
        match encapsulate_mlkem_from_rng(suite, keypair.public_key(), &mut rng) {
            Err(MlKemError::Rng(RngError)) => {}
            Ok(_) => panic!("ML-KEM encapsulation seed RNG failure must be reported"),
            Err(other) => panic!("expected ML-KEM encapsulation RNG error, got {other:?}"),
        }
    }
    #[test]
    fn from_rng_encapsulation_rejects_all_zero_seed_material() {
        let suite = MlKemSuite::MlKem512;
        let keypair = generate_mlkem_keypair_from_seed(
            suite,
            HedgedRngSeed::from_entropy([0xA7; 32]),
            b"inert-encap-keygen",
        )
        .expect("seeded ML-KEM keypair generation should succeed");
        let mut rng = FixedPqSeedRng { seed: [0_u8; 32] };
        match encapsulate_mlkem_from_rng(suite, keypair.public_key(), &mut rng) {
            Err(MlKemError::Rng(RngError)) => {}
            Ok(_) => panic!("ML-KEM encapsulation all-zero seed material must be rejected"),
            Err(other) => panic!("expected ML-KEM inert encapsulation seed error, got {other:?}"),
        }
    }
    #[test]
    fn direct_keypair_rejects_all_zero_coin_material() {
        let suite = MlKemSuite::MlKem512;
        let err = generate_mlkem_keypair_from_coins(suite, &[0_u8; 64])
            .expect_err("all-zero ML-KEM keypair coins must be rejected");
        match err {
            MlKemError::InertKeyMaterial {
                suite: actual,
                kind,
            } => {
                assert_eq!(actual, suite);
                assert_eq!(kind, "ML-KEM keypair coins");
            }
            other => panic!("expected ML-KEM inert keypair coin error, got {other:?}"),
        }
    }
    #[test]
    fn direct_encapsulation_rejects_all_zero_coin_material() {
        let suite = MlKemSuite::MlKem512;
        let keypair = generate_mlkem_keypair_from_seed(
            suite,
            HedgedRngSeed::from_entropy([0xA8; 32]),
            b"inert-encap-coins-keygen",
        )
        .expect("seeded ML-KEM keypair generation should succeed");
        let err = encapsulate_mlkem_from_coins(suite, keypair.public_key(), &[0_u8; 32])
            .expect_err("all-zero ML-KEM encapsulation coins must be rejected");
        match err {
            MlKemError::InertKeyMaterial {
                suite: actual,
                kind,
            } => {
                assert_eq!(actual, suite);
                assert_eq!(kind, "ML-KEM encapsulation coins");
            }
            other => panic!("expected ML-KEM inert encapsulation coin error, got {other:?}"),
        }
    }
    #[test]
    fn checked_keypair_generation_validates_output() {
        for suite in MlKemSuite::ALL {
            let mut rng = hedged_chacha20_rng(
                HedgedRngSeed::from_entropy([suite.kem_id().wrapping_add(0x90); 32]),
                b"checked-keygen",
            );
            let keys = generate_mlkem_keypair(suite, &mut rng).expect("keygen succeeds");
            validate_mlkem_key_pair(suite, keys.public_key(), keys.secret_key())
                .expect("checked ML-KEM keypair validates");
        }
    }
    #[test]
    fn generated_keypair_validator_rejects_public_secret_mismatch() {
        let suite = MlKemSuite::MlKem512;
        let keypair = generate_mlkem_keypair_from_seed(
            suite,
            HedgedRngSeed::from_entropy([0xE2; 32]),
            b"generated-keypair-mismatch",
        )
        .expect("seeded ML-KEM keypair generation should succeed");
        let mut mismatched = MlKemKeyPair {
            public_key: keypair.public_key().to_vec(),
            secret_key: Zeroizing::new(keypair.secret_key().to_vec()),
        };
        mismatched.public_key[0] ^= 0x80;
        let err = validate_generated_mlkem_keypair(suite, &mismatched)
            .expect_err("generated ML-KEM keypair mismatch must fail");
        assert!(matches!(
            err,
            MlKemError::KeyPairMismatch {
                suite: MlKemSuite::MlKem512,
                ..
            }
        ));
    }
    #[test]
    fn seeded_keypair_is_deterministic() {
        for suite in MlKemSuite::ALL {
            let seed = HedgedRngSeed::from_entropy([suite.kem_id().wrapping_add(0xA0); 32]);
            let first = generate_mlkem_keypair_from_seed(suite, seed.clone(), b"seeded-keygen")
                .expect("first seeded keygen succeeds");
            let second = generate_mlkem_keypair_from_seed(suite, seed, b"seeded-keygen")
                .expect("second seeded keygen succeeds");
            assert_eq!(first.public_key(), second.public_key());
            assert_eq!(first.secret_key(), second.secret_key());
        }
    }
    #[test]
    fn seeded_keypair_rejects_all_zero_seed_material() {
        for suite in MlKemSuite::ALL {
            let err = generate_mlkem_keypair_from_seed(
                suite,
                HedgedRngSeed::from_entropy([0_u8; 32]),
                b"seeded-keygen",
            )
            .expect_err("all-zero ML-KEM keypair seed material must be rejected");
            match err {
                MlKemError::InertKeyMaterial {
                    suite: actual,
                    kind,
                } => {
                    assert_eq!(actual, suite);
                    assert_eq!(kind, "ML-KEM seed material");
                }
                other => panic!("unexpected ML-KEM all-zero keypair seed error: {other:?}"),
            }
        }
    }
    #[test]
    fn seeded_keypair_personalization_changes_output() {
        for suite in MlKemSuite::ALL {
            let seed = HedgedRngSeed::from_entropy([suite.kem_id().wrapping_add(0xA8); 32]);
            let first = generate_mlkem_keypair_from_seed(suite, seed.clone(), b"seeded-keygen-a")
                .expect("first seeded keygen succeeds");
            let second = generate_mlkem_keypair_from_seed(suite, seed, b"seeded-keygen-b")
                .expect("second seeded keygen succeeds");
            assert_ne!(first.public_key(), second.public_key());
            assert_ne!(first.secret_key(), second.secret_key());
        }
    }
    #[test]
    fn seeded_encapsulation_is_deterministic() {
        for suite in MlKemSuite::ALL {
            let key_seed = HedgedRngSeed::from_entropy([suite.kem_id().wrapping_add(0xB0); 32]);
            let enc_seed = HedgedRngSeed::from_entropy([suite.kem_id().wrapping_add(0xC0); 32]);
            let keys = generate_mlkem_keypair_from_seed(suite, key_seed, b"seeded-enc-keygen")
                .expect("seeded keygen succeeds");
            let (first_shared, first_ct) =
                encapsulate_mlkem_from_seed(suite, keys.public_key(), enc_seed.clone(), b"enc")
                    .expect("seeded encapsulation succeeds");
            let (second_shared, second_ct) =
                encapsulate_mlkem_from_seed(suite, keys.public_key(), enc_seed, b"enc")
                    .expect("seeded encapsulation succeeds");
            assert_eq!(first_ct.as_bytes(), second_ct.as_bytes());
            assert_eq!(first_shared.as_bytes(), second_shared.as_bytes());
        }
    }
    #[test]
    fn seeded_encapsulation_rejects_all_zero_seed_material() {
        for suite in MlKemSuite::ALL {
            let key_seed = HedgedRngSeed::from_entropy([suite.kem_id().wrapping_add(0xB8); 32]);
            let keys = generate_mlkem_keypair_from_seed(suite, key_seed, b"seeded-enc-keygen")
                .expect("seeded keygen succeeds");
            let err = encapsulate_mlkem_from_seed(
                suite,
                keys.public_key(),
                HedgedRngSeed::from_entropy([0_u8; 32]),
                b"enc",
            )
            .expect_err("all-zero ML-KEM encapsulation seed material must be rejected");
            match err {
                MlKemError::InertKeyMaterial {
                    suite: actual,
                    kind,
                } => {
                    assert_eq!(actual, suite);
                    assert_eq!(kind, "ML-KEM seed material");
                }
                other => {
                    panic!("unexpected ML-KEM all-zero encapsulation seed error: {other:?}")
                }
            }
        }
    }
    #[test]
    fn seeded_encapsulation_personalization_changes_output() {
        let suite = MlKemSuite::MlKem768;
        let key_seed = HedgedRngSeed::from_entropy([0xB7; 32]);
        let enc_seed = HedgedRngSeed::from_entropy([0xC7; 32]);
        let keys = generate_mlkem_keypair_from_seed(suite, key_seed, b"seeded-enc-keygen")
            .expect("seeded keygen succeeds");
        let (first_shared, first_ct) =
            encapsulate_mlkem_from_seed(suite, keys.public_key(), enc_seed.clone(), b"enc-a")
                .expect("seeded encapsulation succeeds");
        let (second_shared, second_ct) =
            encapsulate_mlkem_from_seed(suite, keys.public_key(), enc_seed, b"enc-b")
                .expect("seeded encapsulation succeeds");
        assert_ne!(first_ct.as_bytes(), second_ct.as_bytes());
        assert_ne!(first_shared.as_bytes(), second_shared.as_bytes());
    }
    #[test]
    fn invalid_public_key_length() {
        let mut rng = hedged_chacha20_rng(
            HedgedRngSeed::from_entropy([0xFE; 32]),
            b"mlkem-invalid-public-key",
        );
        let err = encapsulate_mlkem(MlKemSuite::MlKem512, &[0u8; 8], &mut rng).unwrap_err();
        match err {
            MlKemError::BadEncoding { kind, .. } => assert!(kind.contains("public key")),
            MlKemError::KeyPairMismatch { .. }
            | MlKemError::KeyPairPublicHashMismatch { .. }
            | MlKemError::InertKeyMaterial { .. }
            | MlKemError::NonCanonicalEncoding { .. } => {
                panic!("unexpected key-pair mismatch")
            }
            MlKemError::BackendFailure { .. } => panic!("unexpected backend failure"),
            MlKemError::Rng(_) => panic!("unexpected RNG error"),
        }
    }
    #[test]
    fn encapsulation_helpers_reject_invalid_public_key_before_entropy() {
        let suite = MlKemSuite::MlKem512;
        let short_public_key = [0u8; 8];
        let mut rng = deterministic_chacha20_rng(
            HedgedRngSeed::from_entropy([0xF1; 32]),
            b"mlkem-invalid-public-key-preflight",
        );
        for (label, result) in [
            (
                "direct",
                encapsulate_mlkem(suite, &short_public_key, &mut rng),
            ),
            (
                "seeded",
                encapsulate_mlkem_from_seed(
                    suite,
                    &short_public_key,
                    HedgedRngSeed::from_entropy([0xF2; 32]),
                    b"invalid-public-key",
                ),
            ),
            ("os", encapsulate_mlkem_from_os(suite, &short_public_key)),
        ] {
            match result {
                Err(MlKemError::BadEncoding { kind, .. }) => assert!(
                    kind.contains("public key"),
                    "{label} helper should reject the public key length"
                ),
                other => panic!("unexpected {label} result: {other:?}"),
            }
        }
    }
    #[test]
    fn decapsulation_rejects_invalid_secret_and_ciphertext_lengths() {
        let suite = MlKemSuite::MlKem512;
        let keys = generate_mlkem_keypair_from_seed(
            suite,
            HedgedRngSeed::from_entropy([0xDA; 32]),
            b"decap-length-keygen",
        )
        .expect("seeded keygen succeeds");
        let (_, ciphertext) = encapsulate_mlkem_from_seed(
            suite,
            keys.public_key(),
            HedgedRngSeed::from_entropy([0xDB; 32]),
            b"decap-length-enc",
        )
        .expect("encapsulation succeeds");
        let short_secret = &keys.secret_key()[..keys.secret_key().len() - 1];
        let err =
            decapsulate_mlkem(suite, short_secret, ciphertext.as_bytes()).expect_err("bad secret");
        match err {
            MlKemError::BadEncoding { kind, .. } => assert!(kind.contains("secret key")),
            MlKemError::KeyPairMismatch { .. }
            | MlKemError::KeyPairPublicHashMismatch { .. }
            | MlKemError::InertKeyMaterial { .. }
            | MlKemError::NonCanonicalEncoding { .. } => {
                panic!("unexpected key-pair mismatch")
            }
            MlKemError::BackendFailure { .. } => panic!("unexpected backend failure"),
            MlKemError::Rng(_) => panic!("unexpected RNG error"),
        }
        let short_ciphertext = &ciphertext.as_bytes()[..ciphertext.as_bytes().len() - 1];
        let err =
            decapsulate_mlkem(suite, keys.secret_key(), short_ciphertext).expect_err("bad ct");
        match err {
            MlKemError::BadEncoding { kind, .. } => assert!(kind.contains("ciphertext")),
            MlKemError::KeyPairMismatch { .. }
            | MlKemError::KeyPairPublicHashMismatch { .. }
            | MlKemError::InertKeyMaterial { .. }
            | MlKemError::NonCanonicalEncoding { .. } => {
                panic!("unexpected key-pair mismatch")
            }
            MlKemError::BackendFailure { .. } => panic!("unexpected backend failure"),
            MlKemError::Rng(_) => panic!("unexpected RNG error"),
        }
    }
    #[test]
    fn validation_rejects_all_zero_ciphertext_material() {
        for suite in MlKemSuite::ALL {
            let all_zero_ciphertext = vec![0_u8; suite.ciphertext_len()];
            let err = validate_mlkem_ciphertext(suite, all_zero_ciphertext.as_slice())
                .expect_err("all-zero ML-KEM ciphertext must fail validation");
            assert_inert_key_material(err, suite, "ciphertext");
        }
    }
    #[test]
    fn decapsulation_rejects_all_zero_ciphertext_material() {
        let suite = MlKemSuite::MlKem768;
        let keys = generate_mlkem_keypair_from_seed(
            suite,
            HedgedRngSeed::from_entropy([0xD0; 32]),
            b"all-zero-ciphertext-keygen",
        )
        .expect("seeded keygen succeeds");
        let all_zero_ciphertext = vec![0_u8; suite.ciphertext_len()];
        let err = decapsulate_mlkem(suite, keys.secret_key(), all_zero_ciphertext.as_slice())
            .expect_err("all-zero ML-KEM ciphertext must fail before decapsulation");
        assert_inert_key_material(err, suite, "ciphertext");
    }
    #[test]
    fn decapsulation_with_wrong_secret_does_not_match_sender_secret() {
        let suite = MlKemSuite::MlKem768;
        let recipient = generate_mlkem_keypair_from_seed(
            suite,
            HedgedRngSeed::from_entropy([0xDC; 32]),
            b"wrong-secret-recipient",
        )
        .expect("recipient keygen succeeds");
        let wrong_recipient = generate_mlkem_keypair_from_seed(
            suite,
            HedgedRngSeed::from_entropy([0xDD; 32]),
            b"wrong-secret-recipient",
        )
        .expect("wrong recipient keygen succeeds");
        let (sender_shared, ciphertext) = encapsulate_mlkem_from_seed(
            suite,
            recipient.public_key(),
            HedgedRngSeed::from_entropy([0xDE; 32]),
            b"wrong-secret-enc",
        )
        .expect("encapsulation succeeds");
        let wrong_shared =
            decapsulate_mlkem(suite, wrong_recipient.secret_key(), ciphertext.as_bytes())
                .expect("ML-KEM decapsulation returns an implicit-rejection secret");
        assert_ne!(sender_shared.as_bytes(), wrong_shared.as_bytes());
    }
    #[test]
    fn decapsulation_with_tampered_ciphertext_does_not_match_sender_secret() {
        let suite = MlKemSuite::MlKem768;
        let recipient = generate_mlkem_keypair_from_seed(
            suite,
            HedgedRngSeed::from_entropy([0xD1; 32]),
            b"tampered-ciphertext-recipient",
        )
        .expect("recipient keygen succeeds");
        let (sender_shared, ciphertext) = encapsulate_mlkem_from_seed(
            suite,
            recipient.public_key(),
            HedgedRngSeed::from_entropy([0xD2; 32]),
            b"tampered-ciphertext-enc",
        )
        .expect("encapsulation succeeds");
        let mut tampered = ciphertext.as_bytes().to_vec();
        tampered[0] ^= 0x80;
        let tampered_shared = decapsulate_mlkem(suite, recipient.secret_key(), &tampered)
            .expect("ML-KEM decapsulation returns an implicit-rejection secret");
        assert_ne!(sender_shared.as_bytes(), tampered_shared.as_bytes());
    }
    #[test]
    fn encapsulation_rejects_public_key_from_different_suite() {
        let keypair = generate_mlkem_keypair_from_seed(
            MlKemSuite::MlKem512,
            HedgedRngSeed::from_entropy([0xDF; 32]),
            b"wrong-suite-public-key",
        )
        .expect("seeded keygen succeeds");
        let mut rng =
            deterministic_chacha20_rng(HedgedRngSeed::from_entropy([0xE7; 32]), b"wrong-suite-enc");
        let err = encapsulate_mlkem(MlKemSuite::MlKem768, keypair.public_key(), &mut rng)
            .expect_err("ML-KEM-512 public key must not validate as ML-KEM-768");
        match err {
            MlKemError::BadEncoding { kind, .. } => assert!(kind.contains("public key")),
            MlKemError::KeyPairMismatch { .. }
            | MlKemError::KeyPairPublicHashMismatch { .. }
            | MlKemError::InertKeyMaterial { .. }
            | MlKemError::NonCanonicalEncoding { .. } => {
                panic!("unexpected key-pair mismatch")
            }
            MlKemError::BackendFailure { .. } => panic!("unexpected backend failure"),
            MlKemError::Rng(_) => panic!("unexpected RNG error"),
        }
    }
    #[test]
    fn validation_accepts_generated_exact_lengths() {
        for suite in MlKemSuite::ALL {
            let keys = generate_mlkem_keypair_from_seed(
                suite,
                HedgedRngSeed::from_entropy([suite.kem_id().wrapping_add(0xE0); 32]),
                b"exact-length-keygen",
            )
            .expect("seeded keygen succeeds");
            let (_, ciphertext) = encapsulate_mlkem_from_seed(
                suite,
                keys.public_key(),
                HedgedRngSeed::from_entropy([suite.kem_id().wrapping_add(0xE8); 32]),
                b"exact-length-enc",
            )
            .expect("encapsulation succeeds");
            validate_mlkem_public_key(suite, keys.public_key()).expect("public key validates");
            validate_mlkem_secret_key(suite, keys.secret_key()).expect("secret key validates");
            validate_mlkem_ciphertext(suite, ciphertext.as_bytes()).expect("ciphertext validates");
        }
    }
    #[test]
    fn validation_rejects_noncanonical_public_key_coefficients() {
        for suite in MlKemSuite::ALL {
            let keys = generate_mlkem_keypair_from_seed(
                suite,
                HedgedRngSeed::from_entropy([suite.kem_id().wrapping_add(0xDA); 32]),
                b"noncanonical-public-key",
            )
            .expect("seeded keygen succeeds");
            let mut public_key = keys.public_key().to_vec();
            set_first_public_key_coefficient_noncanonical(&mut public_key);
            let err = validate_mlkem_public_key(suite, public_key.as_slice())
                .expect_err("noncanonical public key must fail validation");
            assert_noncanonical_public_key(err, suite);
            let err = encapsulate_mlkem_from_seed(
                suite,
                public_key.as_slice(),
                HedgedRngSeed::from_entropy([suite.kem_id().wrapping_add(0xDB); 32]),
                b"noncanonical-public-encapsulation",
            )
            .expect_err("noncanonical public key must fail before encapsulation");
            assert_noncanonical_public_key(err, suite);
        }
    }
    #[test]
    fn validation_rejects_all_zero_public_key_material() {
        for suite in MlKemSuite::ALL {
            let all_zero_public = vec![0_u8; suite.public_key_len()];
            let err = validate_mlkem_public_key(suite, all_zero_public.as_slice())
                .expect_err("all-zero ML-KEM public key must fail validation");
            assert_inert_key_material(err, suite, "public key");
            let err = encapsulate_mlkem_from_seed(
                suite,
                all_zero_public.as_slice(),
                HedgedRngSeed::from_entropy([suite.kem_id().wrapping_add(0xE1); 32]),
                b"all-zero-public-encapsulation",
            )
            .expect_err("all-zero ML-KEM public key must fail before encapsulation");
            assert_inert_key_material(err, suite, "public key");
        }
    }
    #[test]
    fn secret_key_embeds_generated_public_key_for_each_suite() {
        for suite in MlKemSuite::ALL {
            let keys = generate_mlkem_keypair_from_seed(
                suite,
                HedgedRngSeed::from_entropy([suite.kem_id().wrapping_add(0xF0); 32]),
                b"embedded-public-key",
            )
            .expect("seeded keygen succeeds");
            assert_eq!(
                suite
                    .public_key_from_secret_key(keys.secret_key())
                    .expect("secret key embeds public key"),
                keys.public_key()
            );
            assert_eq!(
                suite
                    .public_key_hash_from_secret_key(keys.secret_key())
                    .expect("secret key embeds public-key hash"),
                mlkem_public_key_hash(keys.public_key()).as_slice()
            );
            validate_mlkem_key_pair(suite, keys.public_key(), keys.secret_key())
                .expect("generated ML-KEM key pair validates");
        }
    }
    #[test]
    fn validation_rejects_mismatched_key_pair() {
        let suite = MlKemSuite::MlKem768;
        let keys = generate_mlkem_keypair_from_seed(
            suite,
            HedgedRngSeed::from_entropy([0xF4; 32]),
            b"keypair-mismatch-a",
        )
        .expect("seeded keygen succeeds");
        let other = generate_mlkem_keypair_from_seed(
            suite,
            HedgedRngSeed::from_entropy([0xF5; 32]),
            b"keypair-mismatch-b",
        )
        .expect("seeded keygen succeeds");
        let err = validate_mlkem_key_pair(suite, keys.public_key(), other.secret_key())
            .expect_err("mismatched ML-KEM key pair must fail");
        assert!(matches!(
            err,
            MlKemError::KeyPairMismatch {
                suite: MlKemSuite::MlKem768,
                ..
            }
        ));
    }
    #[test]
    fn validation_rejects_secret_key_public_hash_drift() {
        let suite = MlKemSuite::MlKem768;
        let keys = generate_mlkem_keypair_from_seed(
            suite,
            HedgedRngSeed::from_entropy([0xF6; 32]),
            b"keypair-hash-drift",
        )
        .expect("seeded keygen succeeds");
        let mut secret_key = keys.secret_key().to_vec();
        secret_key[suite.secret_key_public_key_hash_offset()] ^= 0x80;
        let err = validate_mlkem_key_pair(suite, keys.public_key(), secret_key.as_slice())
            .expect_err("secret-key embedded public hash drift must fail");
        assert!(matches!(
            err,
            MlKemError::KeyPairPublicHashMismatch {
                suite: MlKemSuite::MlKem768,
                ..
            }
        ));
    }
    #[test]
    fn secret_key_validation_rejects_public_hash_drift() {
        let suite = MlKemSuite::MlKem768;
        let keys = generate_mlkem_keypair_from_seed(
            suite,
            HedgedRngSeed::from_entropy([0xF7; 32]),
            b"secret-hash-drift",
        )
        .expect("seeded keygen succeeds");
        let mut secret_key = keys.secret_key().to_vec();
        secret_key[suite.secret_key_public_key_hash_offset()] ^= 0x40;
        let err = validate_mlkem_secret_key(suite, secret_key.as_slice())
            .expect_err("standalone secret-key hash drift must fail");
        assert!(matches!(
            err,
            MlKemError::KeyPairPublicHashMismatch {
                suite: MlKemSuite::MlKem768,
                ..
            }
        ));
    }
    #[test]
    fn secret_key_validation_rejects_noncanonical_embedded_public_key() {
        let suite = MlKemSuite::MlKem768;
        let keys = generate_mlkem_keypair_from_seed(
            suite,
            HedgedRngSeed::from_entropy([0xFA; 32]),
            b"secret-noncanonical-public",
        )
        .expect("seeded keygen succeeds");
        let mut secret_key = keys.secret_key().to_vec();
        let public_start = suite.secret_key_public_key_offset();
        set_first_public_key_coefficient_noncanonical(
            &mut secret_key[public_start..public_start + suite.public_key_len()],
        );
        let public_hash =
            mlkem_public_key_hash(&secret_key[public_start..public_start + suite.public_key_len()]);
        let public_hash_start = suite.secret_key_public_key_hash_offset();
        secret_key[public_hash_start..public_hash_start + MLKEM_PUBLIC_KEY_HASH_BYTES]
            .copy_from_slice(&public_hash);
        let err = validate_mlkem_secret_key(suite, secret_key.as_slice())
            .expect_err("secret-key embedded public key must be canonical");
        assert_noncanonical_public_key(err, suite);
    }
    #[test]
    fn secret_key_validation_rejects_all_zero_embedded_public_key() {
        let suite = MlKemSuite::MlKem768;
        let keys = generate_mlkem_keypair_from_seed(
            suite,
            HedgedRngSeed::from_entropy([0xC8; 32]),
            b"secret-all-zero-embedded-public",
        )
        .expect("seeded keygen succeeds");
        let mut secret_key = keys.secret_key().to_vec();
        let public_start = suite.secret_key_public_key_offset();
        let public_end = public_start + suite.public_key_len();
        secret_key[public_start..public_end].fill(0);
        let public_hash = mlkem_public_key_hash(&secret_key[public_start..public_end]);
        let public_hash_start = suite.secret_key_public_key_hash_offset();
        secret_key[public_hash_start..public_hash_start + MLKEM_PUBLIC_KEY_HASH_BYTES]
            .copy_from_slice(&public_hash);
        let err = validate_mlkem_secret_key(suite, secret_key.as_slice())
            .expect_err("secret-key embedded all-zero public key must fail validation");
        assert_inert_key_material(err, suite, "embedded public key");
    }
    #[test]
    fn secret_key_validation_rejects_all_zero_implicit_rejection_seed() {
        for suite in MlKemSuite::ALL {
            let keys = generate_mlkem_keypair_from_seed(
                suite,
                HedgedRngSeed::from_entropy([suite.kem_id().wrapping_add(0xC9); 32]),
                b"secret-all-zero-implicit-rejection-seed",
            )
            .expect("seeded keygen succeeds");
            let mut secret_key = keys.secret_key().to_vec();
            let seed_start = suite.secret_key_implicit_rejection_seed_offset();
            secret_key[seed_start..].fill(0);
            let err = validate_mlkem_secret_key(suite, secret_key.as_slice())
                .expect_err("all-zero implicit-rejection seed must fail validation");
            assert_inert_key_material(err, suite, "implicit rejection seed");
            let err = validate_mlkem_key_pair(suite, keys.public_key(), secret_key.as_slice())
                .expect_err("all-zero implicit-rejection seed must fail key-pair validation");
            assert_inert_key_material(err, suite, "implicit rejection seed");
        }
    }
    #[test]
    fn secret_key_validation_rejects_noncanonical_private_component() {
        for suite in MlKemSuite::ALL {
            let keys = generate_mlkem_keypair_from_seed(
                suite,
                HedgedRngSeed::from_entropy([suite.kem_id().wrapping_add(0xFC); 32]),
                b"secret-noncanonical-private",
            )
            .expect("seeded keygen succeeds");
            let mut secret_key = keys.secret_key().to_vec();
            set_first_12_bit_coefficient_noncanonical(&mut secret_key);
            let err = validate_mlkem_secret_key(suite, secret_key.as_slice())
                .expect_err("secret-key private component must be canonical");
            assert_noncanonical_encoding(err, suite, "private component");
        }
    }
    #[test]
    fn validation_rejects_all_zero_secret_key_material() {
        for suite in MlKemSuite::ALL {
            let keys = generate_mlkem_keypair_from_seed(
                suite,
                HedgedRngSeed::from_entropy([suite.kem_id().wrapping_add(0xD4); 32]),
                b"all-zero-secret-keypair",
            )
            .expect("seeded keygen succeeds");
            let (_, ciphertext) = encapsulate_mlkem_from_seed(
                suite,
                keys.public_key(),
                HedgedRngSeed::from_entropy([suite.kem_id().wrapping_add(0xD5); 32]),
                b"all-zero-secret-encapsulation",
            )
            .expect("encapsulation succeeds");
            let all_zero_secret = vec![0_u8; suite.secret_key_len()];
            let err = validate_mlkem_secret_key(suite, all_zero_secret.as_slice())
                .expect_err("all-zero ML-KEM secret key must fail validation");
            assert_inert_key_material(err, suite, "secret key");
            let err = validate_mlkem_key_pair(suite, keys.public_key(), all_zero_secret.as_slice())
                .expect_err("all-zero ML-KEM secret key must fail key-pair validation");
            assert_inert_key_material(err, suite, "secret key");
            let err = decapsulate_mlkem(suite, all_zero_secret.as_slice(), ciphertext.as_bytes())
                .expect_err("all-zero ML-KEM secret key must fail before decapsulation");
            assert_inert_key_material(err, suite, "secret key");
        }
    }
    #[test]
    fn decapsulation_rejects_secret_key_public_hash_drift() {
        let suite = MlKemSuite::MlKem768;
        let keys = generate_mlkem_keypair_from_seed(
            suite,
            HedgedRngSeed::from_entropy([0xF8; 32]),
            b"decap-secret-hash-drift",
        )
        .expect("seeded keygen succeeds");
        let (_, ciphertext) = encapsulate_mlkem_from_seed(
            suite,
            keys.public_key(),
            HedgedRngSeed::from_entropy([0xF9; 32]),
            b"decap-secret-hash-drift-enc",
        )
        .expect("encapsulation succeeds");
        let mut secret_key = keys.secret_key().to_vec();
        secret_key[suite.secret_key_public_key_hash_offset()] ^= 0x20;
        let err = decapsulate_mlkem(suite, secret_key.as_slice(), ciphertext.as_bytes())
            .expect_err("corrupted secret-key hash must fail before decapsulation");
        assert!(matches!(
            err,
            MlKemError::KeyPairPublicHashMismatch {
                suite: MlKemSuite::MlKem768,
                ..
            }
        ));
    }
    #[test]
    fn decapsulation_rejects_all_zero_implicit_rejection_seed() {
        let suite = MlKemSuite::MlKem768;
        let keys = generate_mlkem_keypair_from_seed(
            suite,
            HedgedRngSeed::from_entropy([0xCA; 32]),
            b"decap-all-zero-implicit-rejection-seed",
        )
        .expect("seeded keygen succeeds");
        let (_, ciphertext) = encapsulate_mlkem_from_seed(
            suite,
            keys.public_key(),
            HedgedRngSeed::from_entropy([0xCB; 32]),
            b"decap-all-zero-implicit-rejection-seed-enc",
        )
        .expect("encapsulation succeeds");
        let mut secret_key = keys.secret_key().to_vec();
        let seed_start = suite.secret_key_implicit_rejection_seed_offset();
        secret_key[seed_start..].fill(0);
        let err = decapsulate_mlkem(suite, secret_key.as_slice(), ciphertext.as_bytes())
            .expect_err("all-zero implicit-rejection seed must fail before decapsulation");
        assert_inert_key_material(err, suite, "implicit rejection seed");
    }
    #[test]
    fn decapsulation_rejects_noncanonical_secret_key_private_component() {
        let suite = MlKemSuite::MlKem768;
        let keys = generate_mlkem_keypair_from_seed(
            suite,
            HedgedRngSeed::from_entropy([0xFD; 32]),
            b"decap-secret-noncanonical-private",
        )
        .expect("seeded keygen succeeds");
        let (_, ciphertext) = encapsulate_mlkem_from_seed(
            suite,
            keys.public_key(),
            HedgedRngSeed::from_entropy([0xFE; 32]),
            b"decap-secret-noncanonical-private-enc",
        )
        .expect("encapsulation succeeds");
        let mut secret_key = keys.secret_key().to_vec();
        set_first_12_bit_coefficient_noncanonical(&mut secret_key);
        let err = decapsulate_mlkem(suite, secret_key.as_slice(), ciphertext.as_bytes())
            .expect_err("noncanonical secret-key private component must fail before decapsulation");
        assert_noncanonical_encoding(err, suite, "private component");
    }
    #[test]
    fn metadata_names_are_unique_across_suites() {
        let names: Vec<_> = MlKemSuite::ALL
            .iter()
            .map(|suite| suite.metadata().name)
            .collect();
        assert_eq!(names.len(), 3);
        assert_ne!(names[0], names[1]);
        assert_ne!(names[0], names[2]);
        assert_ne!(names[1], names[2]);
    }
    #[test]
    fn mlkem_parameters_align_with_bindings() {
        let params = mlkem_parameters(MlKemSuite::MlKem768);
        assert_eq!(params.public_key, MLKEM768_PUBLIC_KEY_BYTES);
        assert_eq!(params.secret_key, MLKEM768_SECRET_KEY_BYTES);
        assert_eq!(params.ciphertext, MLKEM768_CIPHERTEXT_BYTES);
        assert_eq!(params.shared_secret, MLKEM768_SHARED_SECRET_BYTES);
    }
    #[test]
    fn validation_rejects_short_inputs() {
        let res = validate_mlkem_public_key(MlKemSuite::MlKem1024, &[0u8; 16]);
        assert!(res.is_err());
    }
    #[test]
    fn validation_error_display_includes_kind_and_lengths() {
        let err = validate_mlkem_secret_key(MlKemSuite::MlKem768, &[0u8; 7])
            .expect_err("short secret key must be rejected");
        let rendered = err.to_string();
        assert!(rendered.contains("ML-KEM-768 secret key"));
        assert!(rendered.contains('7'));
        assert!(rendered.contains("2400"));
    }
    #[test]
    fn validation_rejects_long_inputs_for_each_kind() {
        let suite = MlKemSuite::MlKem512;
        let long_public = vec![0u8; suite.public_key_len() + 1];
        let long_secret = vec![0u8; suite.secret_key_len() + 1];
        let long_ciphertext = vec![0u8; suite.ciphertext_len() + 1];
        for (label, result) in [
            ("public key", validate_mlkem_public_key(suite, &long_public)),
            ("secret key", validate_mlkem_secret_key(suite, &long_secret)),
            (
                "ciphertext",
                validate_mlkem_ciphertext(suite, &long_ciphertext),
            ),
        ] {
            match result {
                Err(MlKemError::BadEncoding { kind, .. }) => assert!(
                    kind.contains(label),
                    "expected {kind:?} to mention {label:?}"
                ),
                other => panic!("unexpected validation result for {label}: {other:?}"),
            }
        }
    }
    #[test]
    fn suite_parameters_cover_all_lengths() {
        for suite in MlKemSuite::ALL {
            let via_method = suite.parameters();
            let via_fn = mlkem_parameters(suite);
            assert_eq!(via_method, via_fn);
            assert_eq!(via_method.public_key, suite.public_key_len());
            assert_eq!(via_method.secret_key, suite.secret_key_len());
            assert_eq!(via_method.ciphertext, suite.ciphertext_len());
            assert_eq!(via_method.shared_secret, suite.shared_secret_len());
        }
    }
    #[test]
    fn suite_into_parameters_matches_method() {
        let params_from_into: MlKemParameters = MlKemSuite::MlKem768.into();
        let params_from_method = MlKemSuite::MlKem768.parameters();
        assert_eq!(params_from_into, params_from_method);
    }
    #[test]
    fn metadata_roundtrips_kem_id() {
        for suite in MlKemSuite::ALL {
            let metadata = suite.metadata();
            assert_eq!(metadata.suite, suite);
            assert_eq!(suite.kem_id(), metadata.kem_id);
            assert_eq!(metadata, mlkem_metadata(suite));
            let recovered =
                MlKemSuite::from_kem_id(metadata.kem_id).expect("supported kem identifier");
            assert_eq!(recovered, suite);
        }
        assert!(MlKemSuite::from_kem_id(0xFF).is_none());
    }
    #[test]
    fn metadata_matches_bindings() {
        for suite in MlKemSuite::ALL {
            let metadata = suite.metadata();
            let params = metadata.parameters;
            assert_eq!(params, mlkem_parameters(suite));
            assert_eq!(params, suite.parameters());
            match suite {
                MlKemSuite::MlKem512 => {
                    assert_eq!(metadata.name, "ML-KEM-512");
                    assert_eq!(metadata.security_category, 1);
                    assert_eq!(metadata.symmetric_security_bits, 128);
                    assert_eq!(metadata.module_rank, 2);
                    assert_eq!(metadata.du, 10);
                    assert_eq!(metadata.dv, 4);
                }
                MlKemSuite::MlKem768 => {
                    assert_eq!(metadata.name, "ML-KEM-768");
                    assert_eq!(metadata.security_category, 3);
                    assert_eq!(metadata.symmetric_security_bits, 192);
                    assert_eq!(metadata.module_rank, 3);
                    assert_eq!(metadata.du, 10);
                    assert_eq!(metadata.dv, 4);
                }
                MlKemSuite::MlKem1024 => {
                    assert_eq!(metadata.name, "ML-KEM-1024");
                    assert_eq!(metadata.security_category, 5);
                    assert_eq!(metadata.symmetric_security_bits, 256);
                    assert_eq!(metadata.module_rank, 4);
                    assert_eq!(metadata.du, 11);
                    assert_eq!(metadata.dv, 5);
                }
            }
            assert_eq!(metadata.module_degree, 256);
            assert_eq!(metadata.modulus_q, 3329);
            assert_eq!(metadata.eta2, 2);
            assert_eq!(metadata.parameters.shared_secret, 32);
        }
    }
    #[test]
    fn suite_parsing_requires_canonical_names() {
        assert_eq!(
            MlKemSuite::from_str("mlkem512").unwrap(),
            MlKemSuite::MlKem512
        );
        assert_eq!(
            MlKemSuite::from_str("mlkem768").unwrap(),
            MlKemSuite::MlKem768
        );
        assert_eq!(
            MlKemSuite::from_str("mlkem1024").unwrap(),
            MlKemSuite::MlKem1024
        );
        for rejected in ["kyber512", "KYBER768", "MlKeM1024", "unknown-suite"] {
            assert_eq!(
                MlKemSuite::from_str(rejected).unwrap_err(),
                SuiteParseError(rejected.to_string())
            );
        }
    }
    #[test]
    fn suite_parse_error_display_preserves_input() {
        let err = MlKemSuite::from_str("mlkem999").unwrap_err();
        assert_eq!(err.to_string(), "unknown ML-KEM suite 'mlkem999'");
    }
    #[test]
    fn suite_display_uses_canonical_lowercase_names() {
        assert_eq!(MlKemSuite::MlKem512.to_string(), "mlkem512");
        assert_eq!(MlKemSuite::MlKem768.to_string(), "mlkem768");
        assert_eq!(MlKemSuite::MlKem1024.to_string(), "mlkem1024");
    }
}

#[cfg(test)]
mod initialized_output_tests;

#[cfg(test)]
mod fips203_nistkat_tests;

#[cfg(test)]
mod fips203_acvp_tests;
