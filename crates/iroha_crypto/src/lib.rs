//! This module contains structures and implementations related to the cryptographic parts of the Iroha.
mod algorithm;
#[cfg(doctest)]
mod bfv_api_boundary;
#[cfg(any(test, feature = "bfv-test-fixtures"))]
pub mod bfv_test_fixtures;
#[cfg(feature = "bls")]
mod bls_decode_cache;
#[cfg(test)]
mod captured_schema_tests;
mod confidential;
#[cfg(feature = "pqc")]
pub mod confidential_memo;
/// Authenticated, process-local spooling for bounded confidential chunks.
pub mod confidential_spool;
#[cfg(feature = "bls")]
/// Verification primitives for drand BLS12-381 randomness beacons.
pub mod drand;
/// Symmetric/asymmetric encryption utilities.
pub mod encryption;
/// Baseline BFV fully homomorphic encryption primitives.
pub mod fhe_bfv;
mod hash;
#[cfg(feature = "pqc")]
/// Hybrid KEM/DEM helpers used by SoraFS payload envelopes.
pub mod hybrid;
/// Qualified-provider cryptography for KAGEMUSHA V1 credit envelopes.
pub mod kagemusha;
/// Key exchange protocols.
pub mod kex;
mod merkle;
mod merkle_map;
#[cfg(feature = "pqc")]
mod mldsa_seed;
/// ML-DSA-65 typed-key operations with the shared portable `AArch64` fallback.
#[cfg(feature = "pqc")]
pub use soranet_pq::{sign_mldsa65_detached, verify_mldsa65_detached};
mod multihash;
/// Lane privacy commitment registry (NX-10).
pub mod privacy;
mod protocol_key;
/// RAM-LFE commitment and evaluation interfaces.
pub mod ram_lfe;
pub(crate) mod rng;
#[cfg(feature = "bls")]
/// Fixed-suite threshold-BLS public transcript and signature validation.
pub mod threshold_bls;
#[cfg(feature = "bls")]
/// Folded timed Open Vote Network ballots with intrinsic threshold release.
pub mod timed_ovn;
#[cfg(feature = "bls")]
/// Generic timelock-encryption KEM/DEM helpers outside the folded ballot path.
pub mod tle;
/// SHAKE256 expansion into caller-owned buffers.
pub mod xof;
/// Deterministic dual-`rand_core` RNG used by protocols that must replay an
/// exact prover-randomness schedule from secret seed material.
pub use rng::rng_from_seed_slice;
mod secrecy;
mod signature;
pub mod sorafs;
#[cfg(feature = "pqc")]
pub mod soranet;
#[cfg(feature = "pqc")]
pub mod streaming;
#[cfg(test)]
mod test_allocations;
/// Canonical exact numeric facade for lower-level authenticated protocol crates.
///
/// These are direct re-exports, so their type identity and Norito encoding are
/// exactly those of `iroha_primitives`; the facade lets protocol crates already
/// anchored on `iroha_crypto` avoid an otherwise unnecessary dependency edge.
pub mod numeric {
    pub use iroha_primitives::numeric::{
        Numeric, NumericOperationError, Quantity, RoundingMode, XOR_QUANTITY_SCALE, XorQuantity,
        XorQuantityError,
    };
}
#[cfg(test)]
mod numeric_facade_tests {
    #[test]
    fn quantity_facade_preserves_type_identity_and_wire_roundtrip() {
        let direct: iroha_primitives::numeric::Quantity =
            "1.25".parse().expect("canonical quantity");
        let facade: super::numeric::Quantity = direct;
        let bytes = norito::to_bytes(&facade).expect("encode facade quantity");
        let decoded = norito::decode_from_bytes::<iroha_primitives::numeric::Quantity>(&bytes)
            .expect("decode direct quantity");
        assert_eq!(decoded, facade);
    }
}
#[cfg(feature = "sm")]
pub mod sm;
mod varint;
#[cfg(feature = "bls")]
/// Verifiable Random Function (VRF) based on BLS12-381 signatures.
///
/// This module exposes a simple VRF interface where the proof is a BLS
/// signature over a pre-hashed input with an Iroha-specific domain tag and the
/// output is a 32-byte Blake2b hash of the signature bytes with a distinct
/// domain tag. The construction avoids cross-protocol collisions with regular
/// signatures and keeps verification simple and efficient.
///
/// Determinism and cross-arch stability:
/// - The message prehash uses raw Blake2b-256 over
///   `b"iroha:vrf:v1:input|" || network_id[32] || "|" || input`.
/// - Proofs are BLS signatures produced by the canonical BLS implementation in
///   this crate; verification accepts the same bytes.
/// - Outputs are computed as raw Blake2b-256 over
///   `b"iroha:vrf:v1:output" || proof_bytes`.
pub mod vrf;
#[cfg(feature = "bls")]
pub use self::signature::bls::{
    BlsNormal, BlsNormalPrivateKey, BlsNormalPublicKey, BlsSmall, BlsSmallPrivateKey,
    BlsSmallPublicKey, ETHEREUM_BLS_POP_DST, ethereum_bls_pop_fast_aggregate_verify,
    ethereum_bls_pop_validate_public_key,
};
pub use blake2;
mod prepared_decode;
pub use prepared_decode::{
    PreparedCryptoDecodeError, PreparedPublicKeyDecode, PreparedSignatureDecode,
};
mod public_key_allocation;
mod public_key_decode;
mod public_key_input;
use core::{fmt, str::FromStr};
pub use public_key_allocation::{ChargedPublicKey, PublicKeyAllocationError};
pub use public_key_input::PublicKeyEnvelopeError;
pub use signature::admission::{SignatureVerificationError, verify_signature_borrowed};
#[cfg(feature = "bls")]
pub use signature::admission::{
    verify_bls_normal_pop_borrowed, verify_bls_normal_signature_borrowed,
};
#[cfg(feature = "bls")]
pub use signature::bls::aggregate_custody::BlsNormalAggregateScratch;
#[cfg(any(feature = "bls", feature = "pqc"))]
use std::sync::Arc;
#[cfg(feature = "bls")]
use std::sync::{Mutex, OnceLock};
use std::{
    borrow::{Cow, ToOwned as _},
    boxed::Box,
    format,
    string::{String, ToString as _},
    vec,
    vec::Vec,
};
/// Convenience alias for the historical Blake2b-256 digest type which was
/// previously exported directly from the `blake2` crate. The upstream crate
/// removed this alias in 0.10, so we offer it here to keep the existing API
/// surface for downstream users.
pub type Blake2b256 = blake2::Blake2b<blake2::digest::consts::U32>;
pub use confidential::{
    ConfidentialKeyError, ConfidentialKeyset, derive_keyset, derive_keyset_from_slice,
    generate_keyset,
};
use derive_more::Display;
pub use error::Error;
use error::ParseError;
pub use fhe_bfv::*;
use getset::Getters;
pub use hash::*;
#[cfg(feature = "pqc")]
pub use hybrid::{
    DerivedSecret as HybridDerivedSecret, HybridError, HybridKemCiphertext, HybridKeyPair,
    HybridPublicKey, HybridSecretKey, HybridSuite, decapsulate as hybrid_decapsulate,
    encapsulate as hybrid_encapsulate,
};
use iroha_primitives::const_vec::ConstVec;
use iroha_schema::{Declaration, IntoSchema, MetaMap, Metadata, NamedFieldsMeta, TypeId};
pub use merkle::{CompactMerkleProof, MerkleError, MerkleProof, MerkleTree, MerkleTreeCommitment};
pub use merkle_map::{
    MAX_NORITO_DOMAIN_BYTES, MAX_NORITO_KEY_BYTES, MAX_NORITO_RANGE_PROOF_BYTES,
    MAX_NORITO_RANGE_ROWS, MAX_NORITO_TREE_ENTRIES, MAX_NORITO_TREE_PAYLOAD_BYTES,
    MAX_NORITO_VALUE_BYTES, MerkleMap, MerkleMapEdit, MerkleMapError, MerkleMapLookupProof,
    MerkleMapNode, MerkleMapNodeRef, MerkleMapNodeStore, MerkleMapProof, MerkleMapProofStep,
    MerkleMapRangeError, MerkleMapRangeProof, MerkleMapReadError, MerkleMapRoot,
    MerkleMapStoreNode, MerkleMapUpdateError, MerkleMapUpdateWorkspace, MerkleMapValueRef,
    NoritoKeyDigestRangeProofV1, NoritoKeyDigestRangeTreeV1, NoritoKeyRangeError,
    NoritoKeyRangeExternalProofV1, NoritoKeyRangeExternalV1, NoritoKeyRangeNodeStoreV1,
    NoritoKeyRangeProofV1, NoritoKeyRangeTreeV1, NoritoKeyRangeVerifyRequestV1,
    VerifiedNoritoKeyDigestRangeV1, VerifiedNoritoKeyRangeExternalV1, VerifiedNoritoKeyRangeV1,
    digest_norito_value_frame_v1,
};
pub use privacy::{
    CommitmentScheme, LaneCommitmentId, LanePrivacyCommitment, MerkleCommitment, MerkleWitness,
    PrivacyError, PrivacyWitness, lane_merkle_leaf_hash, lane_merkle_node_hash,
};
pub use protocol_key::derive_non_signing_ed25519_public_key;
pub use ram_lfe::*;
#[cfg(feature = "sm")]
pub use sm::{Sm2PrivateKey, Sm2PublicKey, Sm2Signature, Sm3Digest, Sm4Key};
#[cfg(feature = "bls")]
use w3f_bls::SerializableToBytes;
// Zeroize trait is only required under configurations that use it.
pub use self::signature::secp256k1::EcdsaSecp256k1Sha256;
pub use self::signature::*;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
#[cfg(feature = "gost")]
pub mod gost {
    //! Public wrapper exposing the GOST signature helpers.
    pub use super::signature::gost::*;
}
use crate::secrecy::Secret;
pub use algorithm::{Algorithm, ED_25519, SECP_256_K1};
#[cfg(feature = "bls")]
pub use algorithm::{BLS_NORMAL, BLS_SMALL};

/// Securely wipe a supported value before confidential discard.
///
/// This bridge lets dependent crates erase scalars and containers using
/// [`zeroize::Zeroize`]'s volatile writes and compiler fences without taking a
/// separate dependency on `zeroize`. The value may intentionally become
/// invalid and must not be used after this call.
pub fn zeroize_value_for_confidential_discard<T: Zeroize + ?Sized>(value: &mut T) {
    <T as Zeroize>::zeroize(value);
}

/// Domain separator for BLS Proof-of-Possession over a validator public key.
/// Message = Hash("iroha:bls:pop:v1" || `pk_bytes`)
#[cfg(feature = "bls")]
const POP_DST: &str = "iroha:bls:pop:v1";
fn is_all_zero_material(bytes: &[u8]) -> bool {
    !bytes.is_empty() && bytes.iter().all(|&byte| byte == 0)
}
#[cfg(all(test, feature = "pqc"))]
std::thread_local! {
    static PUBLIC_KEY_VALIDATION_CALLS: core::cell::Cell<usize> =
        const { core::cell::Cell::new(0) };
}
#[cfg(all(test, feature = "pqc"))]
fn record_public_key_validation_call() {
    PUBLIC_KEY_VALIDATION_CALLS.with(|calls| calls.set(calls.get() + 1));
}
#[cfg(all(test, feature = "pqc"))]
fn reset_public_key_validation_call_count() {
    PUBLIC_KEY_VALIDATION_CALLS.with(|calls| calls.set(0));
}
#[cfg(all(test, feature = "pqc"))]
fn public_key_validation_call_count() -> usize {
    PUBLIC_KEY_VALIDATION_CALLS.with(core::cell::Cell::get)
}
// ML-DSA-65 wire widths are stable protocol constants. Keep them available
// when the optional native PQC backend is disabled so
// parsers preserve the same framing and algorithm discriminant.
const ML_DSA_65_PUBLIC_KEY_BYTES: usize = 1_952;
const ML_DSA_65_SIGNATURE_BYTES: usize = 3_309;
/// Protocol-wide ceiling for the raw payload of any canonical public key.
///
/// This excludes the one-byte algorithm tag stored by [`PublicKey`]. The
/// largest accepted payload is an SM2 envelope: a two-byte identifier-length
/// field, at most `u16::MAX / 8` identifier bytes because SM2 carries that
/// length in bits, and a 65-byte uncompressed SEC1 point. The ceiling remains
/// feature-independent so admission and transport geometry cannot vary with
/// compiled algorithms.
pub const MAX_PUBLIC_KEY_PAYLOAD_BYTES: usize = 2 + (u16::MAX as usize / 8) + 65;

/// Validate only the structural wire envelope of a compact public key.
/// Successful checks allocate no backing; ordinary failure diagnostics own text.
///
/// Cryptographic validity is established at every public constructor and
/// decoder. Serializers nevertheless reject structurally forged in-crate
/// values without reparsing keys or consulting algorithm caches.
fn validate_public_key_structural_envelope(
    algorithm: Algorithm,
    payload: &[u8],
) -> Result<(), ParseError> {
    let exact_len = |expected: usize| {
        (payload.len() == expected && !is_all_zero_material(payload))
            .then_some(())
            .ok_or_else(|| ParseError("invalid public key structural envelope".to_owned()))
    };
    match algorithm {
        Algorithm::Ed25519 => exact_len(32),
        Algorithm::Secp256k1 => {
            exact_len(33)?;
            matches!(payload.first().copied(), Some(0x02 | 0x03))
                .then_some(())
                .ok_or_else(|| ParseError("invalid secp256k1 public key envelope".to_owned()))
        }
        Algorithm::MlDsa => exact_len(ML_DSA_65_PUBLIC_KEY_BYTES),
        #[cfg(feature = "bls")]
        Algorithm::BlsNormal => exact_len(48),
        #[cfg(feature = "bls")]
        Algorithm::BlsSmall => exact_len(96),
        #[cfg(feature = "gost")]
        Algorithm::Gost3410_2012_256ParamSetA
        | Algorithm::Gost3410_2012_256ParamSetB
        | Algorithm::Gost3410_2012_256ParamSetC => exact_len(64),
        #[cfg(feature = "gost")]
        Algorithm::Gost3410_2012_512ParamSetA | Algorithm::Gost3410_2012_512ParamSetB => {
            exact_len(128)
        }
        #[cfg(feature = "sm")]
        Algorithm::Sm2 => {
            const PREFIX_BYTES: usize = 2;
            const SEC1_BYTES: usize = 65;
            let prefix: [u8; PREFIX_BYTES] = payload
                .get(..PREFIX_BYTES)
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or_else(|| ParseError("invalid SM2 public key envelope".to_owned()))?;
            let distid_len = usize::from(u16::from_be_bytes(prefix));
            if distid_len > usize::from(u16::MAX) / 8 {
                return Err(ParseError("invalid SM2 public key envelope".to_owned()));
            }
            let sec1_start = PREFIX_BYTES
                .checked_add(distid_len)
                .ok_or_else(|| ParseError("invalid SM2 public key envelope".to_owned()))?;
            let expected = sec1_start
                .checked_add(SEC1_BYTES)
                .ok_or_else(|| ParseError("invalid SM2 public key envelope".to_owned()))?;
            if payload.len() != expected
                || core::str::from_utf8(&payload[PREFIX_BYTES..sec1_start]).is_err()
                || payload.get(sec1_start) != Some(&0x04)
            {
                return Err(ParseError("invalid SM2 public key envelope".to_owned()));
            }
            Ok(())
        }
    }
}

/// Key pair generation option. Passed to a specific algorithm.
pub enum KeyGenOption<K> {
    /// Use random number generator
    #[cfg(feature = "rand")]
    Random,
    /// Deterministically derive from secret seed material.
    ///
    /// This option does not estimate or add entropy. Production callers must
    /// supply a secret seed with at least 256 bits of entropy; public values,
    /// labels, and passwords are unsafe inputs.
    UseSeed(Vec<u8>),
    /// Derive from a private key
    FromPrivateKey(K),
}
impl<K> fmt::Debug for KeyGenOption<K> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(feature = "rand")]
            Self::Random => formatter.write_str("Random"),
            Self::UseSeed(seed) => formatter
                .debug_struct("UseSeed")
                .field("len", &seed.len())
                .finish(),
            Self::FromPrivateKey(_) => formatter.write_str("FromPrivateKey([REDACTED])"),
        }
    }
}
/// Pair of Public and Private keys.
#[derive(Clone, PartialEq, Eq, Getters, Debug)]
#[getset(get = "pub")]
pub struct KeyPair {
    /// Public key.
    public_key: PublicKey,
    /// Private key.
    private_key: PrivateKey,
}
#[cfg(feature = "rand")]
impl KeyPair {
    /// Fallibly generate a random key pair using a default [`Algorithm`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeyGen`] when the selected algorithm cannot generate an
    /// internally consistent key pair.
    pub fn try_random() -> Result<Self, Error> {
        Self::try_random_with_algorithm(Algorithm::default())
    }
    /// Generate a random key pair using a default [`Algorithm`].
    pub fn random() -> Self {
        Self::try_random().expect("random key generation should succeed for the default algorithm")
    }
    /// Fallibly generate a random key pair.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeyGen`] when the selected algorithm cannot generate an
    /// internally consistent key pair.
    pub fn try_random_with_algorithm(algorithm: Algorithm) -> Result<Self, Error> {
        match algorithm {
            Algorithm::Ed25519 => {
                ed25519::Ed25519Sha512::try_keypair(KeyGenOption::Random).map(Into::into)
            }
            Algorithm::Secp256k1 => {
                secp256k1::EcdsaSecp256k1Sha256::try_keypair(KeyGenOption::Random).map(Into::into)
            }
            #[cfg(feature = "pqc")]
            Algorithm::MlDsa => mldsa_seed::mldsa65::random_keypair()
                .and_then(|(public_key, private_key)| KeyPair::new(public_key, private_key)),
            #[cfg(not(feature = "pqc"))]
            Algorithm::MlDsa => Err(Error::KeyGen(String::from(
                "ML-DSA backend is unavailable on this target",
            ))),
            #[cfg(feature = "gost")]
            Algorithm::Gost3410_2012_256ParamSetA
            | Algorithm::Gost3410_2012_256ParamSetB
            | Algorithm::Gost3410_2012_256ParamSetC
            | Algorithm::Gost3410_2012_512ParamSetA
            | Algorithm::Gost3410_2012_512ParamSetB => {
                let (public, secret) = signature::gost::generate_random_keypair(algorithm)?;
                let public_key = PublicKey(PublicKeyCompact::new(algorithm, public.as_bytes()));
                let private_key = PrivateKey(Box::new(Secret::new(PrivateKeyInner::Gost {
                    algorithm,
                    secret,
                })));
                KeyPair::new(public_key, private_key)
            }
            #[cfg(feature = "bls")]
            Algorithm::BlsNormal => bls::BlsNormal::try_keypair(KeyGenOption::Random)
                .map(Into::into)
                .map_err(|err| Error::KeyGen(err.to_string())),
            #[cfg(feature = "bls")]
            Algorithm::BlsSmall => bls::BlsSmall::try_keypair(KeyGenOption::Random)
                .map(Into::into)
                .map_err(|err| Error::KeyGen(err.to_string())),
            #[cfg(feature = "sm")]
            Algorithm::Sm2 => {
                let mut rng = rand::rngs::OsRng;
                let private =
                    sm::Sm2PrivateKey::try_random(sm::Sm2PublicKey::default_distid(), &mut rng)
                        .map_err(|err| Error::KeyGen(err.to_string()))?;
                let public_key = private
                    .try_public_key()
                    .and_then(Sm2PublicKey::into_compact)
                    .map_err(|err| Error::KeyGen(err.to_string()))?;
                let private_key = PrivateKey(Box::new(Secret::new(PrivateKeyInner::Sm2(private))));
                KeyPair::new(public_key, private_key)
            }
        }
    }
    /// Generate a random key pair
    pub fn random_with_algorithm(algorithm: Algorithm) -> Self {
        Self::try_random_with_algorithm(algorithm)
            .expect("random key generation should succeed for supported algorithms")
    }
}
impl KeyPair {
    /// Fallibly derive a key pair from seed material.
    ///
    /// Ed25519 uses the seed directly when 32 bytes are provided; other lengths are
    /// hashed with SHA-256 to obtain a canonical 32-byte seed.
    /// ML-DSA-65 derives its FIPS 204 key-generation seed through a
    /// domain-separated HKDF-SHA-512 expansion.
    ///
    /// Deterministic derivation does not add entropy. Production callers must
    /// supply secret seed material with at least 256 bits of entropy. Prefer
    /// [`KeyPair::try_random_with_algorithm`] when reproducibility is not
    /// required.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeyGen`] when the selected algorithm cannot derive an
    /// internally consistent key pair from the seed material.
    pub fn try_from_seed(seed: Vec<u8>, algorithm: Algorithm) -> Result<Self, Error> {
        match algorithm {
            Algorithm::Ed25519 => {
                ed25519::Ed25519Sha512::try_keypair(KeyGenOption::UseSeed(seed)).map(Into::into)
            }
            Algorithm::Secp256k1 => {
                secp256k1::EcdsaSecp256k1Sha256::try_keypair(KeyGenOption::UseSeed(seed))
                    .map(Into::into)
            }
            #[cfg(feature = "pqc")]
            Algorithm::MlDsa => {
                let seed = Zeroizing::new(seed);
                let (public, private) = mldsa_seed::mldsa65::keypair_from_seed(seed.as_slice())?;
                KeyPair::new(public, private)
            }
            #[cfg(not(feature = "pqc"))]
            Algorithm::MlDsa => Err(Error::KeyGen(String::from(
                "ML-DSA backend is unavailable on this target",
            ))),
            #[cfg(feature = "gost")]
            Algorithm::Gost3410_2012_256ParamSetA
            | Algorithm::Gost3410_2012_256ParamSetB
            | Algorithm::Gost3410_2012_256ParamSetC
            | Algorithm::Gost3410_2012_512ParamSetA
            | Algorithm::Gost3410_2012_512ParamSetB => {
                let seed = Zeroizing::new(seed);
                let (public, secret) =
                    signature::gost::generate_seeded_keypair(algorithm, seed.as_slice())?;
                let public_key = PublicKey(PublicKeyCompact::new(algorithm, public.as_bytes()));
                let private_key = PrivateKey(Box::new(Secret::new(PrivateKeyInner::Gost {
                    algorithm,
                    secret,
                })));
                KeyPair::new(public_key, private_key)
            }
            #[cfg(feature = "bls")]
            Algorithm::BlsNormal => bls::BlsNormal::try_keypair(KeyGenOption::UseSeed(seed))
                .map(Into::into)
                .map_err(|err| Error::KeyGen(err.to_string())),
            #[cfg(feature = "bls")]
            Algorithm::BlsSmall => bls::BlsSmall::try_keypair(KeyGenOption::UseSeed(seed))
                .map(Into::into)
                .map_err(|err| Error::KeyGen(err.to_string())),
            #[cfg(feature = "sm")]
            Algorithm::Sm2 => {
                let seed = Zeroizing::new(seed);
                let private_inner =
                    sm::Sm2PrivateKey::from_seed(Sm2PublicKey::default_distid(), seed.as_slice())
                        .map_err(|err| Error::KeyGen(err.to_string()))?;
                let public_key = private_inner
                    .try_public_key()
                    .and_then(Sm2PublicKey::into_compact)
                    .map_err(|err| Error::KeyGen(err.to_string()))?;
                let private_key =
                    PrivateKey(Box::new(Secret::new(PrivateKeyInner::Sm2(private_inner))));
                KeyPair::new(public_key, private_key)
            }
        }
    }
    /// Derive a key pair from seed material.
    ///
    /// Ed25519 uses the seed directly when 32 bytes are provided; other lengths are
    /// hashed with SHA-256 to obtain a canonical 32-byte seed.
    /// ML-DSA-65 derives its FIPS 204 key-generation seed through a
    /// domain-separated HKDF-SHA-512 expansion.
    ///
    /// Deterministic derivation does not add entropy. Production callers must
    /// supply secret seed material with at least 256 bits of entropy.
    pub fn from_seed(seed: Vec<u8>, algorithm: Algorithm) -> Self {
        Self::try_from_seed(seed, algorithm)
            .expect("seeded key generation should succeed for supported algorithms")
    }
    /// Algorithm
    pub fn algorithm(&self) -> Algorithm {
        self.private_key.algorithm()
    }
    /// Construct a [`KeyPair`].
    ///
    /// See [`Self::into_parts`] for an opposite conversion.
    ///
    /// # Errors
    /// Returns [`Error::Parse`] if the public key payload is malformed, or
    /// [`Error::KeyGen`] if public and private keys don't make a pair.
    pub fn new(public_key: PublicKey, private_key: PrivateKey) -> Result<Self, Error> {
        let algorithm = private_key.algorithm();
        let (public_algorithm, public_payload) = public_key.try_to_bytes()?;
        let public_full = parse_public_key_material(public_algorithm, public_payload)?;
        #[cfg(not(feature = "gost"))]
        let _ = &public_full;
        if algorithm != public_algorithm {
            return Err(Error::KeyGen("Mismatch of key algorithms".to_owned()));
        }
        #[cfg(feature = "gost")]
        if matches!(
            algorithm,
            Algorithm::Gost3410_2012_256ParamSetA
                | Algorithm::Gost3410_2012_256ParamSetB
                | Algorithm::Gost3410_2012_256ParamSetC
                | Algorithm::Gost3410_2012_512ParamSetA
                | Algorithm::Gost3410_2012_512ParamSetB
        ) {
            use crate::secrecy::ExposeSecret;
            let gost_public = match &public_full {
                PublicKeyMaterial::Gost { bytes, .. } => *bytes,
                _ => {
                    return Err(Error::Parse(ParseError(
                        "public key algorithm mismatch".to_owned(),
                    )));
                }
            };
            let gost_private = match private_key.0.expose_secret() {
                PrivateKeyInner::Gost { secret, .. } => secret,
                _ => unreachable!("algorithm indicates GOST"),
            };
            signature::gost::validate_key_pair(algorithm, gost_public, gost_private)
                .map_err(|err| Error::KeyGen(err.to_string()))?;
        }
        #[cfg(feature = "pqc")]
        if algorithm == Algorithm::MlDsa {
            use crate::secrecy::ExposeSecret;
            let secret_bytes = match private_key.0.expose_secret() {
                PrivateKeyInner::MlDsa(bytes) => bytes,
                _ => unreachable!("Algorithm is ML-DSA"),
            };
            let derived_public =
                mldsa_seed::mldsa65::public_key_from_secret(secret_bytes.as_secret())
                    .map_err(|err| Error::KeyGen(err.to_string()))?;
            let (_, derived_payload) = derived_public.try_to_bytes()?;
            if derived_payload != public_payload {
                return Err(Error::KeyGen(String::from("Key pair mismatch")));
            }
            return Ok(Self {
                public_key,
                private_key,
            });
        }
        #[cfg(not(feature = "pqc"))]
        if algorithm == Algorithm::MlDsa {
            return Err(Error::KeyGen(String::from(
                "ML-DSA backend is unavailable on this target",
            )));
        }
        if PublicKey::from(private_key.clone()) != public_key {
            return Err(Error::KeyGen(String::from("Key pair mismatch")));
        }
        Ok(Self {
            public_key,
            private_key,
        })
    }
    /// Get [`PublicKey`] and [`PrivateKey`] contained in the [`KeyPair`].
    pub fn into_parts(self) -> (PublicKey, PrivateKey) {
        (self.public_key, self.private_key)
    }
    /// Construct a [`KeyPair`] from a [`PrivateKey`] by deriving the matching [`PublicKey`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeyGen`] if the derived public key does not correspond to the provided
    /// private key material.
    pub fn from_private_key(private_key: PrivateKey) -> Result<Self, Error> {
        #[cfg(feature = "gost")]
        if matches!(
            private_key.algorithm(),
            Algorithm::Gost3410_2012_256ParamSetA
                | Algorithm::Gost3410_2012_256ParamSetB
                | Algorithm::Gost3410_2012_256ParamSetC
                | Algorithm::Gost3410_2012_512ParamSetA
                | Algorithm::Gost3410_2012_512ParamSetB
        ) {
            use crate::secrecy::ExposeSecret;
            let algorithm = private_key.algorithm();
            let gost_private = match private_key.0.expose_secret() {
                PrivateKeyInner::Gost { secret, .. } => secret,
                _ => unreachable!("algorithm indicates GOST"),
            };
            let derived = signature::gost::derive_public_key(algorithm, gost_private)
                .map_err(|err| Error::KeyGen(err.to_string()))?;
            let public_key = PublicKey(PublicKeyCompact::new(algorithm, derived.as_bytes()));
            return KeyPair::new(public_key, private_key);
        }
        let public_key = PublicKey::from_private_key(&private_key)?;
        Self::new(public_key, private_key)
    }
}
/// Derives full [`KeyPair`] from its [`PrivateKey`] only.
impl From<PrivateKey> for KeyPair {
    fn from(value: PrivateKey) -> Self {
        KeyPair::from_private_key(value).expect(
            "deriving a key pair from a private key should succeed for supported algorithms",
        )
    }
}
impl From<(ed25519::PublicKey, ed25519::PrivateKey)> for KeyPair {
    fn from((public_key, private_key): (ed25519::PublicKey, ed25519::PrivateKey)) -> Self {
        Self {
            public_key: PublicKey::new(PublicKeyFull::Ed25519(public_key)),
            private_key: PrivateKey(Box::new(Secret::new(PrivateKeyInner::Ed25519(private_key)))),
        }
    }
}
impl From<(secp256k1::PublicKey, secp256k1::PrivateKey)> for KeyPair {
    fn from((public_key, private_key): (secp256k1::PublicKey, secp256k1::PrivateKey)) -> Self {
        Self {
            public_key: PublicKey::new(PublicKeyFull::Secp256k1(public_key)),
            private_key: PrivateKey(Box::new(Secret::new(PrivateKeyInner::Secp256k1(
                private_key,
            )))),
        }
    }
}
#[cfg(feature = "bls")]
impl From<(bls::BlsNormalPublicKey, bls::BlsNormalPrivateKey)> for KeyPair {
    fn from(
        (public_key, private_key): (bls::BlsNormalPublicKey, bls::BlsNormalPrivateKey),
    ) -> Self {
        Self {
            public_key: PublicKey::new(PublicKeyFull::from_bls_normal_key(public_key)),
            private_key: PrivateKey(Box::new(Secret::new(PrivateKeyInner::BlsNormal(
                private_key,
            )))),
        }
    }
}
#[cfg(feature = "bls")]
impl From<(bls::BlsSmallPublicKey, bls::BlsSmallPrivateKey)> for KeyPair {
    fn from((public_key, private_key): (bls::BlsSmallPublicKey, bls::BlsSmallPrivateKey)) -> Self {
        Self {
            public_key: PublicKey::new(PublicKeyFull::from_bls_small_key(&public_key)),
            private_key: PrivateKey(Box::new(Secret::new(PrivateKeyInner::BlsSmall(
                private_key,
            )))),
        }
    }
}

/// Validated ML-DSA/SM2 material borrows its original canonical envelope.
/// Only owned decoded material enters the decoded-key cache.
#[cfg_attr(
    all(feature = "bls", not(feature = "sm")),
    expect(
        clippy::large_enum_variant,
        reason = "decoded BLS material stays inline so canonical key admission does not introduce an additional heap allocation"
    )
)]
enum PublicKeyMaterial<'a> {
    MlDsa(&'a [u8]),
    #[cfg(feature = "gost")]
    Gost {
        algorithm: Algorithm,
        bytes: &'a [u8],
    },
    #[cfg(feature = "sm")]
    Sm2(sm::verification::BorrowedKey<'a>),
    Decoded(PublicKeyFull),
}
impl PublicKeyMaterial<'_> {
    fn into_public_key(self) -> PublicKey {
        match self {
            Self::MlDsa(bytes) => PublicKey(PublicKeyCompact::new(Algorithm::MlDsa, bytes)),
            #[cfg(feature = "gost")]
            Self::Gost { algorithm, bytes } => PublicKey(PublicKeyCompact::new(algorithm, bytes)),
            #[cfg(feature = "sm")]
            Self::Sm2(key) => PublicKey(PublicKeyCompact::new(Algorithm::Sm2, key.payload())),
            Self::Decoded(key) => PublicKey::new(key),
        }
    }
}

/// Decoded version of public key (requires more memory).
/// Used only for signature verification.
#[derive(Clone)]
enum PublicKeyFull {
    Ed25519(ed25519::PublicKey),
    Secp256k1(secp256k1::PublicKey),
    #[cfg(feature = "bls")]
    BlsNormal {
        key: bls::BlsNormalPublicKey,
        bytes: Vec<u8>,
    },
    #[cfg(feature = "bls")]
    BlsSmall {
        key: bls::BlsSmallPublicKey,
        bytes: Vec<u8>,
    },
}
fn parse_public_key_material(
    algorithm: Algorithm,
    payload: &[u8],
) -> Result<PublicKeyMaterial<'_>, ParseError> {
    #[cfg(all(test, feature = "pqc"))]
    record_public_key_validation_call();
    match algorithm {
        Algorithm::Ed25519 => {
            ed25519::Ed25519Sha512::parse_public_key(payload).map(PublicKeyFull::Ed25519)
        }
        Algorithm::Secp256k1 => {
            secp256k1::EcdsaSecp256k1Sha256::parse_public_key(payload).map(PublicKeyFull::Secp256k1)
        }
        Algorithm::MlDsa => {
            signature::mldsa::validate_public_key(payload)
                .map_err(signature::mldsa::KeyRejection::into_parse_error)?;
            return Ok(PublicKeyMaterial::MlDsa(payload));
        }
        #[cfg(feature = "gost")]
        Algorithm::Gost3410_2012_256ParamSetA
        | Algorithm::Gost3410_2012_256ParamSetB
        | Algorithm::Gost3410_2012_256ParamSetC
        | Algorithm::Gost3410_2012_512ParamSetA
        | Algorithm::Gost3410_2012_512ParamSetB => {
            signature::gost::validate_public_key(algorithm, payload)
                .map_err(signature::gost::KeyRejection::into_parse_error)?;
            return Ok(PublicKeyMaterial::Gost {
                algorithm,
                bytes: payload,
            });
        }
        #[cfg(feature = "bls")]
        Algorithm::BlsNormal => {
            bls::BlsNormal::parse_public_key(payload).map(PublicKeyFull::from_bls_normal_key)
        }
        #[cfg(feature = "bls")]
        Algorithm::BlsSmall => bls::BlsSmall::parse_public_key(payload)
            .map(|key| PublicKeyFull::from_bls_small_key(&key)),
        #[cfg(feature = "sm")]
        Algorithm::Sm2 => {
            return sm::verification::BorrowedKey::parse(payload)
                .map(PublicKeyMaterial::Sm2)
                .map_err(sm::verification::KeyRejection::into_parse_error);
        }
    }
    .map(PublicKeyMaterial::Decoded)
}
impl PublicKeyFull {
    #[cfg(feature = "bls")]
    fn from_bls_normal_key(key: bls::BlsNormalPublicKey) -> Self {
        let bytes = key.to_bytes();
        Self::BlsNormal { key, bytes }
    }
    #[cfg(feature = "bls")]
    fn from_bls_small_key(key: &bls::BlsSmallPublicKey) -> Self {
        let bytes = key.to_bytes();
        Self::BlsSmall { key: *key, bytes }
    }
    /// Borrow canonical bytes when the decoded key already retains them.
    fn payload(&self) -> Cow<'_, [u8]> {
        match self {
            Self::Ed25519(key) => Cow::Borrowed(key.as_bytes()),
            Self::Secp256k1(key) => Cow::Owned(key.to_sec1_bytes().to_vec()),
            #[cfg(feature = "bls")]
            Self::BlsNormal { bytes, .. } | Self::BlsSmall { bytes, .. } => Cow::Borrowed(bytes),
        }
    }
    fn algorithm(&self) -> Algorithm {
        match self {
            Self::Ed25519(_) => Algorithm::Ed25519,
            Self::Secp256k1(_) => Algorithm::Secp256k1,
            #[cfg(feature = "bls")]
            Self::BlsNormal { .. } => Algorithm::BlsNormal,
            #[cfg(feature = "bls")]
            Self::BlsSmall { .. } => Algorithm::BlsSmall,
        }
    }
}
impl<'a> TryFrom<&'a PublicKeyCompact> for PublicKeyMaterial<'a> {
    type Error = ParseError;
    fn try_from(public_key: &'a PublicKeyCompact) -> Result<Self, Self::Error> {
        parse_public_key_material(public_key.try_algorithm()?, public_key.try_payload()?)
    }
}
/// Encoded version of public key (requires less memory).
/// Any public keys should be stored in such form to reduce memory consumption.
/// In case signature verification is needed, it will be decoded.
///
/// Invariant: `payload` is valid, that is conversion to full form must not give error.
#[derive(Clone, Debug, PartialEq, Eq, norito::NoritoSchema)]
#[norito_schema(name = "iroha_crypto::PublicKeyCompact")]
#[repr(transparent)]
pub struct PublicKeyCompact {
    // First byte corresponds to algorithm
    // Other bytes are payload
    algorithm_and_payload: ConstVec<u8>,
    // This is non-optimized version of this struct:
    // algorithm: Algorithm,
    // payload: ConstVec<u8>,
}

impl Zeroize for PublicKeyCompact {
    fn zeroize(&mut self) {
        let mut bytes = core::mem::take(&mut self.algorithm_and_payload).into_vec();
        bytes.zeroize();
        self.algorithm_and_payload = ConstVec::from(bytes);
    }
}
/// Parsed Ed25519 public key for hot-path verification reuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ed25519ParsedPublicKey(signature::ed25519::PublicKey);
/// Reusable scratch storage for Ed25519 batch verification.
#[derive(Debug, Default)]
pub struct Ed25519BatchScratch<'a> {
    public_keys: Vec<signature::ed25519::PublicKey>,
    signatures: Vec<ed25519_dalek::Signature>,
    miss_messages: Vec<&'a [u8]>,
    miss_raw_signatures: Vec<&'a [u8]>,
    miss_original_indices: Vec<usize>,
}
impl Ed25519BatchScratch<'_> {
    /// Clear retained scratch contents while keeping allocated capacity.
    pub fn clear(&mut self) {
        self.public_keys.clear();
        self.signatures.clear();
        self.miss_messages.clear();
        self.miss_raw_signatures.clear();
        self.miss_original_indices.clear();
    }
}
impl Ed25519ParsedPublicKey {
    /// Raw canonical Ed25519 public-key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}
// Batch verification helpers (deterministic), exposed for admission-time grouping
// across transaction signatures.
/// Parse an Ed25519 public key once for reuse in batch verification.
///
/// # Errors
/// Returns [`Error::Parse`] if the key payload is not a canonical, non-weak Ed25519 public key.
pub fn ed25519_parse_public_key(payload: &[u8]) -> Result<Ed25519ParsedPublicKey, Error> {
    signature::ed25519::Ed25519Sha512::parse_public_key(payload)
        .map(Ed25519ParsedPublicKey)
        .map_err(Error::from)
}
/// Check a fixed Ed25519 public-key candidate against the canonical strict key relation.
///
/// This performs the same canonical-encoding, non-weak-point and prime-order-subgroup checks
/// as [`PublicKey::from_bytes`] for [`Algorithm::Ed25519`], without consulting or populating
/// the parse cache. Success and rejection allocate no key backing or error text.
#[must_use]
pub fn ed25519_public_key_is_valid(candidate: &[u8; 32]) -> bool {
    signature::ed25519::Ed25519Sha512::parse_public_key_uncached_for_decode(candidate).is_ok()
}
/// Parse raw Ed25519 signature bytes for admission before storing them as an opaque signature.
///
/// # Errors
/// Returns [`Error::BadSignature`] if the payload length is invalid or the
/// signature `R` component is malformed, non-canonical, small-order, or outside
/// the prime-order subgroup.
/// Returns [`Error::Parse`] if the payload is empty or all zero.
pub fn ed25519_parse_signature(payload: &[u8]) -> Result<Signature, Error> {
    if payload.is_empty() || payload.iter().all(|byte| *byte == 0) {
        return Err(Error::Parse(ParseError(
            "signature payload must not be empty or all zero".to_owned(),
        )));
    }
    signature::ed25519::Ed25519Sha512::parse_signature(payload)?;
    Signature::try_from_bytes_for_admission(payload)
        .map_err(|_| Error::Parse(ParseError("invalid Ed25519 signature".to_owned())))
}
/// Parse raw ML-DSA-65 signature bytes for admission before storing them as an opaque signature.
///
/// # Errors
/// Returns [`Error::BadSignature`] if the payload length is invalid or the
/// detached signature encoding is malformed. Returns [`Error::Parse`] if the
/// payload is empty or all zero.
pub fn mldsa65_parse_signature(payload: &[u8]) -> Result<Signature, Error> {
    if payload.is_empty() || payload.iter().all(|byte| *byte == 0) {
        return Err(Error::Parse(ParseError(
            "signature payload must not be empty or all zero".to_owned(),
        )));
    }
    if payload.len() != ML_DSA_65_SIGNATURE_BYTES {
        return Err(Error::BadSignature);
    }
    #[cfg(feature = "pqc")]
    {
        use pqcrypto_mldsa::mldsa65;
        use pqcrypto_traits::sign::DetachedSignature as _;
        mldsa65::DetachedSignature::from_bytes(payload).map_err(|_| Error::BadSignature)?;
    }
    Signature::try_from_bytes_for_admission(payload)
        .map_err(|_| Error::Parse(ParseError("invalid ML-DSA signature".to_owned())))
}

/// Verify an externally admitted signature without consulting persistent key
/// or success caches for every admitted signature algorithm.
///
/// BLS uses the same fixed parser and contextual relation as ordinary
/// verification. Public error String materialization is outside that fixed core.
/// GOST uses the shared fixed-width relation and borrows the canonical key bytes.
/// Use [`verify_signature_borrowed`] to retain its typed rejection without
/// materializing the public diagnostic String at this adapter.
///
/// # Errors
/// Returns [`Error::BadSignature`] or a fixed parse error when the signature or
/// public key is invalid for the selected algorithm.
#[doc(hidden)]
pub fn verify_signature_for_admission(
    proof: &Signature,
    public_key: &PublicKey,
    message: &[u8],
) -> Result<(), Error> {
    verify_signature_borrowed(proof, public_key, message)
        .map_err(SignatureVerificationError::into_error)
}
/// Deterministic Ed25519 batch verification wrapper (per-signature).
/// # Errors
/// Returns `Err(Error::BadSignature)` if any `(message, signature, public_key)` tuple fails verification,
/// if the input slices have mismatched lengths, or if the input is empty.
pub fn ed25519_verify_batch_deterministic(
    messages: &[&[u8]],
    signatures: &[&[u8]],
    public_keys: &[&[u8]],
) -> Result<(), Error> {
    signature::ed25519::Ed25519Sha512::verify_batch_deterministic(messages, signatures, public_keys)
}
/// Deterministic Ed25519 batch verification wrapper using pre-parsed public keys.
///
/// Under the `ecc-batch` feature this uses dalek's deterministic batch verifier.
/// Otherwise it retains ordered per-signature fallback behavior.
///
/// # Errors
/// Returns `Err(Error::BadSignature)` if any tuple fails verification, if signatures have invalid
/// length, if the input slices have mismatched lengths, or if the input is empty.
pub fn ed25519_verify_batch_preparsed_deterministic(
    messages: &[&[u8]],
    signatures: &[&[u8]],
    public_keys: &[Ed25519ParsedPublicKey],
) -> Result<(), Error> {
    let mut scratch = Ed25519BatchScratch::default();
    ed25519_verify_batch_preparsed_deterministic_with_scratch(
        messages,
        signatures,
        public_keys,
        &mut scratch,
    )
}
/// Deterministic Ed25519 batch verification wrapper using pre-parsed public keys and caller scratch.
///
/// Reusing `scratch` avoids allocating the dalek key slice for every chunk or
/// deterministic bisection probe in block validation.
///
/// # Errors
/// Returns `Err(Error::BadSignature)` if any tuple fails verification, if signatures have invalid
/// length, if the input slices have mismatched lengths, or if the input is empty.
pub fn ed25519_verify_batch_preparsed_deterministic_with_scratch<'a>(
    messages: &[&'a [u8]],
    signatures: &[&'a [u8]],
    public_keys: &[Ed25519ParsedPublicKey],
    scratch: &mut Ed25519BatchScratch<'a>,
) -> Result<(), Error> {
    ed25519_verify_batch_preparsed_deterministic_with_scratch_inner(
        messages,
        signatures,
        public_keys,
        scratch,
    )
}
fn ed25519_verify_batch_preparsed_deterministic_with_scratch_inner<'a>(
    messages: &[&'a [u8]],
    signatures: &[&'a [u8]],
    public_keys: &[Ed25519ParsedPublicKey],
    scratch: &mut Ed25519BatchScratch<'a>,
) -> Result<(), Error> {
    if messages.is_empty()
        || !(messages.len() == signatures.len() && signatures.len() == public_keys.len())
    {
        return Err(Error::BadSignature);
    }
    scratch.clear();
    scratch
        .miss_original_indices
        .try_reserve(messages.len())
        .map_err(|_| Error::BadSignature)?;
    scratch
        .miss_messages
        .try_reserve(messages.len())
        .map_err(|_| Error::BadSignature)?;
    scratch
        .miss_raw_signatures
        .try_reserve(signatures.len())
        .map_err(|_| Error::BadSignature)?;
    scratch
        .public_keys
        .try_reserve(public_keys.len())
        .map_err(|_| Error::BadSignature)?;
    scratch
        .signatures
        .try_reserve(signatures.len())
        .map_err(|_| Error::BadSignature)?;
    let mut cached_hits = 0usize;
    for (idx, ((message, signature), public_key)) in messages
        .iter()
        .zip(signatures.iter())
        .zip(public_keys.iter())
        .enumerate()
    {
        if signature::ed25519::is_verify_ok_cached(&public_key.0, message, signature) {
            cached_hits = cached_hits.saturating_add(1);
            continue;
        }
        scratch.miss_original_indices.push(idx);
        scratch.miss_messages.push(message);
        scratch.miss_raw_signatures.push(signature);
        scratch
            .signatures
            .push(signature::ed25519::Ed25519Sha512::parse_signature(
                signature,
            )?);
        scratch.public_keys.push(public_key.0);
    }
    if scratch.miss_original_indices.is_empty() {
        return Ok(());
    }
    if cached_hits == 0 {
        return signature::ed25519::Ed25519Sha512::verify_batch_preparsed_signatures_uncached(
            messages,
            signatures,
            &scratch.signatures,
            &scratch.public_keys,
        );
    }
    signature::ed25519::Ed25519Sha512::verify_batch_preparsed_signatures_uncached(
        &scratch.miss_messages,
        &scratch.miss_raw_signatures,
        &scratch.signatures,
        &scratch.public_keys,
    )
}
/// Return the lowest-index failing Ed25519 tuple for pre-parsed public keys.
///
/// The search uses the same deterministic batch verifier as
/// [`ed25519_verify_batch_preparsed_deterministic_with_scratch`] and keeps
/// `scratch` reusable across bisection probes.
#[must_use]
pub fn ed25519_first_bad_preparsed_deterministic_with_scratch<'a>(
    messages: &[&'a [u8]],
    signatures: &[&'a [u8]],
    public_keys: &[Ed25519ParsedPublicKey],
    scratch: &mut Ed25519BatchScratch<'a>,
) -> Option<(usize, String)> {
    ed25519_first_bad_preparsed_deterministic_with_scratch_inner(
        messages,
        signatures,
        public_keys,
        scratch,
    )
}
fn ed25519_first_bad_preparsed_deterministic_with_scratch_inner<'a>(
    messages: &[&'a [u8]],
    signatures: &[&'a [u8]],
    public_keys: &[Ed25519ParsedPublicKey],
    scratch: &mut Ed25519BatchScratch<'a>,
) -> Option<(usize, String)> {
    if messages.is_empty()
        || ed25519_verify_batch_preparsed_deterministic_with_scratch_inner(
            messages,
            signatures,
            public_keys,
            scratch,
        )
        .is_ok()
    {
        return None;
    }
    if messages.len() == 1 {
        let detail = ed25519_verify_batch_preparsed_deterministic_with_scratch_inner(
            messages,
            signatures,
            public_keys,
            scratch,
        )
        .expect_err("single invalid Ed25519 item must fail")
        .to_string();
        return Some((0, detail));
    }
    let split = messages.len() / 2;
    let (left_messages, right_messages) = messages.split_at(split);
    let (left_signatures, right_signatures) = signatures.split_at(split);
    let (left_public_keys, right_public_keys) = public_keys.split_at(split);
    ed25519_first_bad_preparsed_deterministic_with_scratch_inner(
        left_messages,
        left_signatures,
        left_public_keys,
        scratch,
    )
    .or_else(|| {
        ed25519_first_bad_preparsed_deterministic_with_scratch_inner(
            right_messages,
            right_signatures,
            right_public_keys,
            scratch,
        )
        .map(|(idx, detail)| (idx + split, detail))
    })
}
/// Deterministic secp256k1 (ECDSA) batch verification wrapper.
/// Currently verifies each signature independently in the given order.
/// The `seed32` parameter is reserved for future deterministic MSM batching.
/// # Errors
/// Returns `Err(Error::BadSignature)` if any `(message, signature, public_key)` tuple fails verification
/// or if the input slices have mismatched lengths or are empty.
pub fn secp256k1_verify_batch_deterministic(
    messages: &[&[u8]],
    signatures: &[&[u8]],
    public_keys: &[&[u8]],
    seed32: [u8; 32],
) -> Result<(), Error> {
    signature::secp256k1::EcdsaSecp256k1Sha256::verify_batch_deterministic(
        messages,
        signatures,
        public_keys,
        seed32,
    )
}
/// Deterministic ML-DSA-65 batch verification wrapper.
/// Verifies each signature independently.
///
/// # Errors
/// Returns [`Error::BadSignature`] when the input is empty, the input lengths differ,
/// or when signature validation fails.
pub fn pqc_verify_batch_deterministic(
    messages: &[&[u8]],
    signatures: &[&[u8]],
    public_keys: &[&[u8]],
    _seed32: [u8; 32],
) -> Result<(), Error> {
    if messages.is_empty()
        || !(messages.len() == signatures.len() && signatures.len() == public_keys.len())
    {
        return Err(Error::BadSignature);
    }
    for ((message, signature), public_key) in messages.iter().zip(signatures).zip(public_keys) {
        signature::mldsa::verify(public_key, signature, message)
            .map_err(|_| Error::BadSignature)?;
    }
    Ok(())
}
/// Deterministic BLS (normal) batch verification wrapper.
/// Verifies each signature independently using `w3f_bls` (public key in G1, signature in G2).
///
/// # Errors
/// Returns `Err(Error::BadSignature)` on empty input, length mismatches, or if any
/// signature or public key fails to parse or verify.
#[cfg(feature = "bls")]
pub fn bls_normal_verify_batch_deterministic(
    messages: &[&[u8]],
    signatures: &[&[u8]],
    public_keys: &[&[u8]],
    _seed32: [u8; 32],
) -> Result<(), Error> {
    if messages.is_empty()
        || !(messages.len() == signatures.len() && signatures.len() == public_keys.len())
    {
        return Err(Error::BadSignature);
    }
    for ((m, s), pk) in messages
        .iter()
        .zip(signatures.iter())
        .zip(public_keys.iter())
    {
        let vk = signature::bls::BlsNormal::parse_public_key(pk)?;
        signature::bls::BlsNormal::verify(m, s, &vk)?;
    }
    Ok(())
}
/// Deterministic BLS (small) batch verification wrapper.
/// Verifies each signature independently using `w3f_bls` tiny variant.
///
/// # Errors
/// Returns `Err(Error::BadSignature)` on empty input, length mismatches, or if any
/// signature or public key fails to parse or verify.
#[cfg(feature = "bls")]
pub fn bls_small_verify_batch_deterministic(
    messages: &[&[u8]],
    signatures: &[&[u8]],
    public_keys: &[&[u8]],
    _seed32: [u8; 32],
) -> Result<(), Error> {
    if messages.is_empty()
        || !(messages.len() == signatures.len() && signatures.len() == public_keys.len())
    {
        return Err(Error::BadSignature);
    }
    for ((m, s), pk) in messages
        .iter()
        .zip(signatures.iter())
        .zip(public_keys.iter())
    {
        let vk = signature::bls::BlsSmall::parse_public_key(pk)?;
        signature::bls::BlsSmall::verify(m, s, &vk)?;
    }
    Ok(())
}
#[cfg(feature = "bls")]
const BLS_POP_CACHE_CAPACITY: usize = 8_192;
#[cfg(feature = "bls")]
#[derive(Debug, PartialEq, Eq)]
struct BlsPopCacheKey {
    algorithm: Algorithm,
    public_key: Vec<u8>,
    proof: Vec<u8>,
}
#[cfg(feature = "bls")]
impl BlsPopCacheKey {
    fn matches(&self, algorithm: Algorithm, public_key: &[u8], proof: &[u8]) -> bool {
        self.algorithm == algorithm
            && self.public_key.as_slice() == public_key
            && self.proof.as_slice() == proof
    }
}
/// Process-wide cache of successfully verified BLS proofs of possession.
///
/// The digest is only an index. Every hit is confirmed against the exact
/// algorithm, public-key bytes, and proof bytes retained in its collision
/// bucket, so a digest collision cannot turn an unverified proof into a hit.
/// FIFO eviction keeps memory bounded while allowing two complete 4,096-entry
/// Sumeragi validator snapshots to remain resident.
#[cfg(feature = "bls")]
#[derive(Debug, Default)]
struct BlsPopCache {
    entries: std::collections::BTreeMap<Hash, Vec<Arc<BlsPopCacheKey>>>,
    insertion_order: std::collections::VecDeque<(Hash, Arc<BlsPopCacheKey>)>,
}
#[cfg(feature = "bls")]
impl BlsPopCache {
    fn contains(&self, algorithm: Algorithm, public_key: &[u8], proof: &[u8]) -> bool {
        let digest = bls_pop_cache_digest(algorithm, public_key, proof);
        self.contains_at_digest(digest, algorithm, public_key, proof)
    }
    fn contains_at_digest(
        &self,
        digest: Hash,
        algorithm: Algorithm,
        public_key: &[u8],
        proof: &[u8],
    ) -> bool {
        self.entries.get(&digest).is_some_and(|bucket| {
            bucket
                .iter()
                .any(|entry| entry.matches(algorithm, public_key, proof))
        })
    }
    fn remember(&mut self, algorithm: Algorithm, public_key: &[u8], proof: &[u8]) {
        if self.contains(algorithm, public_key, proof) {
            return;
        }
        while self.insertion_order.len() >= BLS_POP_CACHE_CAPACITY {
            self.evict_oldest();
        }
        let digest = bls_pop_cache_digest(algorithm, public_key, proof);
        let entry = Arc::new(BlsPopCacheKey {
            algorithm,
            public_key: public_key.to_vec(),
            proof: proof.to_vec(),
        });
        self.entries.entry(digest).or_default().push(entry.clone());
        self.insertion_order.push_back((digest, entry));
    }
    fn evict_oldest(&mut self) {
        let Some((digest, entry)) = self.insertion_order.pop_front() else {
            return;
        };
        let remove_bucket = self.entries.get_mut(&digest).is_some_and(|bucket| {
            if let Some(position) = bucket
                .iter()
                .position(|candidate| Arc::ptr_eq(candidate, &entry))
            {
                bucket.remove(position);
            }
            bucket.is_empty()
        });
        if remove_bucket {
            self.entries.remove(&digest);
        }
    }
    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.values().map(Vec::len).sum()
    }
}
#[cfg(feature = "bls")]
fn bls_pop_cache() -> &'static Mutex<BlsPopCache> {
    static CACHE: OnceLock<Mutex<BlsPopCache>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(BlsPopCache::default()))
}
#[cfg(feature = "bls")]
fn bls_collect_pks_with_pop<'a>(
    public_keys: &[&'a PublicKey],
    pops: &[&'a [u8]],
    algorithm: Algorithm,
    pop_verify: fn(&PublicKey, &[u8]) -> Result<(), Error>,
) -> Result<Vec<&'a [u8]>, Error> {
    use std::collections::BTreeSet;
    if public_keys.len() != pops.len() || public_keys.is_empty() {
        return Err(Error::BadSignature);
    }
    let mut seen = BTreeSet::new();
    let mut pk_bytes = Vec::with_capacity(public_keys.len());
    for (pk, pop) in public_keys.iter().zip(pops.iter()) {
        let bytes = bls_public_key_payload(pk, algorithm)?;
        if !seen.insert(bytes) {
            return Err(Error::BadSignature);
        }
        pop_verify(pk, pop)?;
        pk_bytes.push(bytes);
    }
    Ok(pk_bytes)
}
#[cfg(feature = "bls")]
fn bls_public_key_payload(pk: &PublicKey, expected: Algorithm) -> Result<&[u8], Error> {
    let (algorithm, payload) = pk.try_to_bytes()?;
    if algorithm != expected {
        return Err(Error::BadSignature);
    }
    Ok(payload)
}
#[cfg(feature = "bls")]
fn bls_pop_cache_key(pk_bytes: &[u8], pop: &[u8]) -> Hash {
    Hash::new_from_chunks(&[pk_bytes, pop])
}
#[cfg(feature = "bls")]
fn bls_pop_cache_digest(algorithm: Algorithm, pk_bytes: &[u8], pop: &[u8]) -> Hash {
    let material = bls_pop_cache_key(pk_bytes, pop);
    Hash::new_from_chunks(&[&[algorithm as u8], material.as_ref()])
}
#[cfg(feature = "bls")]
fn bls_pop_message_hash(pk_bytes: &[u8]) -> [u8; 32] {
    Hash::new_from_chunks(&[POP_DST.as_bytes(), pk_bytes]).into()
}
/// Attempt aggregate verification for BLS (normal) when all messages are identical.
/// Requires a valid Proof-of-Possession (`PoP`) per public key to prevent rogue-key attacks.
/// Aggregate-only check, no per-signature fallback. Deterministic and hardware-stable.
///
/// # Errors
/// Returns `Err(Error::BadSignature)` if any signature/public key fails to parse or verify,
/// or if input slice lengths are inconsistent. Public keys must be unique.
#[cfg(feature = "bls")]
pub fn bls_normal_verify_aggregate_same_message(
    message: &[u8],
    signatures: &[&[u8]],
    public_keys: &[&PublicKey],
    pops: &[&[u8]],
) -> Result<(), Error> {
    if signatures.len() != public_keys.len() || signatures.is_empty() {
        return Err(Error::BadSignature);
    }
    let pk_bytes = bls_collect_pks_with_pop(
        public_keys,
        pops,
        Algorithm::BlsNormal,
        bls_normal_pop_verify,
    )?;
    signature::bls::verify_aggregate_same_message_normal(message, signatures, &pk_bytes)
}
/// Attempt aggregate verification for BLS (normal) when all messages are identical.
/// Requires a valid Proof-of-Possession (`PoP`) per public key to prevent rogue-key attacks.
/// Fast path: aggregate-only check, no per-signature fallback.
///
/// # Errors
/// Returns `Err(Error::BadSignature)` if any signature/public key fails to parse or verify,
/// or if input slice lengths are inconsistent. Public keys must be unique.
#[cfg(feature = "bls")]
pub fn bls_normal_verify_aggregate_same_message_fast(
    message: &[u8],
    signatures: &[&[u8]],
    public_keys: &[&PublicKey],
    pops: &[&[u8]],
) -> Result<(), Error> {
    if signatures.len() != public_keys.len() || signatures.is_empty() {
        return Err(Error::BadSignature);
    }
    let pk_bytes = bls_collect_pks_with_pop(
        public_keys,
        pops,
        Algorithm::BlsNormal,
        bls_normal_pop_verify,
    )?;
    signature::bls::verify_aggregate_same_message_normal(message, signatures, &pk_bytes)
}
/// Exact verification across distinct messages for BLS (normal).
///
/// Every signature is verified independently against the public key and
/// message at the same index. Same-message inputs must use the PoP-enforcing
/// same-message aggregate helpers.
///
/// # Errors
/// Returns `Err(Error::BadSignature)` if any signature/public key fails to parse or verify,
/// if input slice lengths are inconsistent, or if messages are duplicated.
#[cfg(feature = "bls")]
pub fn bls_normal_verify_aggregate_multi_message(
    messages: &[&[u8]],
    signatures: &[&[u8]],
    public_keys: &[&[u8]],
) -> Result<(), Error> {
    signature::bls::verify_aggregate_multi_message_normal(messages, signatures, public_keys)
}
/// Exact verification across distinct messages for BLS (small).
///
/// Every signature is verified independently against the public key and
/// message at the same index. Same-message inputs must use the PoP-enforcing
/// same-message aggregate helpers.
///
/// # Errors
/// Returns `Err(Error::BadSignature)` if any signature/public key fails to parse or verify,
/// if input slice lengths are inconsistent, or if messages are duplicated.
#[cfg(feature = "bls")]
pub fn bls_small_verify_aggregate_multi_message(
    messages: &[&[u8]],
    signatures: &[&[u8]],
    public_keys: &[&[u8]],
) -> Result<(), Error> {
    signature::bls::verify_aggregate_multi_message_small(messages, signatures, public_keys)
}
/// Attempt aggregate verification for BLS (small) when all messages are identical.
/// Requires a valid Proof-of-Possession (`PoP`) per public key to prevent rogue-key attacks.
/// Aggregate-only check, no per-signature fallback.
///
/// # Errors
/// Returns `Err(Error::BadSignature)` if any signature/public key fails to parse or verify,
/// or if input slice lengths are inconsistent. Public keys must be unique.
#[cfg(feature = "bls")]
pub fn bls_small_verify_aggregate_same_message(
    message: &[u8],
    signatures: &[&[u8]],
    public_keys: &[&PublicKey],
    pops: &[&[u8]],
) -> Result<(), Error> {
    if signatures.len() != public_keys.len() || signatures.is_empty() {
        return Err(Error::BadSignature);
    }
    let pk_bytes =
        bls_collect_pks_with_pop(public_keys, pops, Algorithm::BlsSmall, bls_small_pop_verify)?;
    signature::bls::verify_aggregate_same_message_small(message, signatures, &pk_bytes)
}
/// Attempt aggregate verification for BLS (small) when all messages are identical.
/// Requires a valid Proof-of-Possession (`PoP`) per public key to prevent rogue-key attacks.
/// Fast path: aggregate-only check, no per-signature fallback.
///
/// # Errors
/// Returns `Err(Error::BadSignature)` if any signature/public key fails to parse or verify,
/// or if input slice lengths are inconsistent. Public keys must be unique.
#[cfg(feature = "bls")]
pub fn bls_small_verify_aggregate_same_message_fast(
    message: &[u8],
    signatures: &[&[u8]],
    public_keys: &[&PublicKey],
    pops: &[&[u8]],
) -> Result<(), Error> {
    if signatures.len() != public_keys.len() || signatures.is_empty() {
        return Err(Error::BadSignature);
    }
    let pk_bytes =
        bls_collect_pks_with_pop(public_keys, pops, Algorithm::BlsSmall, bls_small_pop_verify)?;
    signature::bls::verify_aggregate_same_message_small(message, signatures, &pk_bytes)
}
/// Aggregate BLS (normal) signatures (same-message) into a single signature.
///
/// # Errors
/// Returns `Err(Error::BadSignature)` if aggregation fails.
#[cfg(feature = "bls")]
pub fn bls_normal_aggregate_signatures(signatures: &[&[u8]]) -> Result<Vec<u8>, Error> {
    signature::bls::aggregate_same_message_normal(signatures)
}
/// Verify a pre-aggregated BLS (normal) signature for the same-message case against a set of public keys.
/// Requires a valid Proof-of-Possession (`PoP`) per public key to prevent rogue-key attacks.
///
/// # Errors
/// Returns `Err(Error::BadSignature)` on parse/verify failure.
#[cfg(feature = "bls")]
pub fn bls_normal_verify_preaggregated_same_message(
    message: &[u8],
    aggregated_signature: &[u8],
    public_keys: &[&PublicKey],
    pops: &[&[u8]],
) -> Result<(), Error> {
    let pk_bytes = bls_collect_pks_with_pop(
        public_keys,
        pops,
        Algorithm::BlsNormal,
        bls_normal_pop_verify,
    )?;
    signature::bls::verify_preaggregated_same_message_normal(
        message,
        aggregated_signature,
        &pk_bytes,
    )
}
/// A BLS-normal public key whose Proof-of-Possession (`PoP`) verified, parsed once.
///
/// Each constructor verifies the `PoP` first, so the
/// type witnesses the rogue-key precondition of aggregate verification: consensus verifies a
/// committee member's `PoP` once, when the member is admitted, and then aggregates its key in
/// every certificate without re-checking or re-parsing it.
#[cfg(feature = "bls")]
#[derive(Clone)]
pub struct BlsNormalPopVerifiedKey {
    public_key: PublicKey,
    point: blstrs::G1Affine,
    // Inline canonical public proof bytes preserve exact local admission identity.
    // This is part of the concrete credential layout, not a detached cache owner.
    proof_of_possession: [u8; 96],
}
#[cfg(feature = "bls")]
impl BlsNormalPopVerifiedKey {
    /// Verify `pop` for the BLS-normal key `public_key` and keep the parsed key.
    ///
    /// # Errors
    /// Returns [`Error::BadSignature`] if the key is not BLS-normal or the proof does not
    /// verify, and a parse error for a malformed key.
    pub fn new(public_key: &PublicKey, pop: &[u8]) -> Result<Self, Error> {
        bls_normal_pop_verify(public_key, pop)?;
        let payload = bls_public_key_payload(public_key, Algorithm::BlsNormal)?;
        let point = signature::bls::parsed_normal_key_borrowed(payload)
            .map_err(signature::bls::uncached::Rejection::into_error)?;
        let proof_of_possession = pop.try_into().map_err(|_| Error::BadSignature)?;
        Ok(Self {
            public_key: public_key.clone(),
            point,
            proof_of_possession,
        })
    }
    /// Verify original owned key material without copying it or retaining a cache entry.
    ///
    /// Success moves the same key backing into the credential. Failure returns
    /// that exact original owner with an unformatted rejection. Both outcomes
    /// allocate no Rust heap backing; the caller retains its existing custody.
    ///
    /// # Errors
    /// Returns the original key and typed envelope/parser/relation rejection if
    /// the BLS-normal proof does not verify. No credential is partially admitted.
    pub fn from_owned_uncached(
        public_key: PublicKey,
        pop: &[u8],
    ) -> Result<Self, (PublicKey, SignatureVerificationError)> {
        match signature::admission::verify_bls_normal_pop_key_borrowed(&public_key, pop) {
            Ok(point) => match pop.try_into() {
                Ok(proof_of_possession) => Ok(Self {
                    public_key,
                    point,
                    proof_of_possession,
                }),
                Err(_) => Err((public_key, SignatureVerificationError::bad_signature())),
            },
            Err(error) => Err((public_key, error)),
        }
    }

    /// Whether `pop` is the exact canonical proof retained by this credential.
    ///
    /// This comparison allocates no backing and performs no new verification.
    /// Callers may reuse only their own already verified credential for the same
    /// public key. A different proof still requires ordinary `PoP` verification.
    #[must_use]
    pub fn proof_of_possession_matches(&self, pop: &[u8]) -> bool {
        self.proof_of_possession.as_slice() == pop
    }

    /// The verified public key.
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }
    /// The raw BLS-normal key bytes (the 48-byte compressed G1 point).
    pub fn payload(&self) -> &[u8] {
        // The constructor extracted this payload successfully from the same key.
        self.public_key
            .try_to_bytes()
            .map_or(&[][..], |(_, payload)| payload)
    }
}
#[cfg(feature = "bls")]
impl fmt::Debug for BlsNormalPopVerifiedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("BlsNormalPopVerifiedKey")
            .field(&self.public_key)
            .finish()
    }
}
#[cfg(feature = "bls")]
impl PartialEq for BlsNormalPopVerifiedKey {
    fn eq(&self, other: &Self) -> bool {
        self.public_key == other.public_key
    }
}
#[cfg(feature = "bls")]
impl Eq for BlsNormalPopVerifiedKey {}
/// Verify ONE pre-aggregated BLS-normal signature over MULTIPLE distinct messages, where the
/// message of each group was signed by every key of that group (e.g. a Sumeragi timeout
/// certificate: its signers grouped by the view of the certificate they carried).
///
/// The keys of each group are aggregated and one multi-pairing checks
/// `e(σ, g) = Π_i e(Σ_{pk ∈ group_i} pk, H(m_i))` (cost: one Miller loop per group plus one).
/// Every key carries a verified `PoP` ([`BlsNormalPopVerifiedKey`]), which makes the
/// per-group (same-message) aggregation rogue-key safe; distinct messages across groups need
/// no further precondition.
///
/// # Errors
/// Returns [`Error::BadSignature`] for no group, an empty group, a key repeated inside a group,
/// a message shared by two groups, a group whose keys sum to the identity, a malformed,
/// non-canonical or identity signature, or a failed pairing check.
#[cfg(feature = "bls")]
pub fn bls_normal_verify_preaggregated_multi_message(
    groups: &[(&[&BlsNormalPopVerifiedKey], &[u8])],
    aggregated_signature: &[u8],
) -> Result<(), Error> {
    let mut scratch = BlsNormalAggregateScratch::new(|_| Ok::<_, core::convert::Infallible>(()))
        .unwrap_or_else(|never| match never {});
    scratch
        .verify(
            groups
                .iter()
                .map(|(keys, message)| (keys.iter().copied(), *message)),
            aggregated_signature,
        )
        .map_err(SignatureVerificationError::into_error)
}
// Note: small-variant pre-aggregated helpers are not exposed; consensus uses BLS-normal only.
/// Verify BLS-Normal Proof-of-Possession (`PoP`) for a given public key.
/// The `PoP` is a BLS signature over `Hash(POP_DST` || `pk_bytes`) using the same
/// BLS-normal ciphersuite as regular signatures.
/// # Errors
/// Returns `Err(Error::BadSignature)` if the public key is not BLS-normal, the proof
/// cannot be parsed, or verification fails.
#[cfg(feature = "bls")]
pub fn bls_normal_pop_verify(pk: &PublicKey, pop: &[u8]) -> Result<(), Error> {
    let pk_bytes = bls_public_key_payload(pk, Algorithm::BlsNormal)?;
    if bls_pop_cache()
        .lock()
        .ok()
        .is_some_and(|cache| cache.contains(Algorithm::BlsNormal, pk_bytes, pop))
    {
        return Ok(());
    }
    let vk = signature::bls::BlsNormal::parse_public_key(pk_bytes)?;
    let msg_hashed = bls_pop_message_hash(pk_bytes);
    signature::bls::BlsNormal::verify(&msg_hashed, pop, &vk)?;
    if let Ok(mut cache) = bls_pop_cache().lock() {
        cache.remember(Algorithm::BlsNormal, pk_bytes, pop);
    }
    Ok(())
}
/// Create BLS-Normal Proof-of-Possession for the corresponding public key.
/// This signs `Hash(POP_DST` || `pk_bytes`) with the provided private key.
///
/// # Errors
/// Returns `Err(Error::BadSignature)` if the private key is not BLS-normal.
#[cfg(feature = "bls")]
pub fn bls_normal_pop_prove(sk: &PrivateKey) -> Result<Vec<u8>, Error> {
    use crate::secrecy::ExposeSecret as _;
    match sk.0.expose_secret() {
        PrivateKeyInner::BlsNormal(_inner) => {
            let pk = PublicKey::from_private_key(sk)?;
            let pk_bytes = bls_public_key_payload(&pk, Algorithm::BlsNormal)?;
            let msg_h = bls_pop_message_hash(pk_bytes);
            signature::bls::BlsNormal::try_sign(
                &msg_h,
                match sk.0.expose_secret() {
                    PrivateKeyInner::BlsNormal(v) => v,
                    _ => unreachable!(),
                },
            )
        }
        _ => Err(Error::BadSignature),
    }
}
/// Verify BLS-Small Proof-of-Possession (`PoP`) for a given public key.
/// The `PoP` is a BLS signature over `Hash(POP_DST` || `pk_bytes`) using the BLS-small ciphersuite.
///
/// # Errors
/// Returns [`Error::BadSignature`] if the key is not BLS-Small, the signature is malformed,
/// or verification fails.
#[cfg(feature = "bls")]
pub fn bls_small_pop_verify(pk: &PublicKey, pop: &[u8]) -> Result<(), Error> {
    let pk_bytes = bls_public_key_payload(pk, Algorithm::BlsSmall)?;
    if bls_pop_cache()
        .lock()
        .ok()
        .is_some_and(|cache| cache.contains(Algorithm::BlsSmall, pk_bytes, pop))
    {
        return Ok(());
    }
    let vk = signature::bls::BlsSmall::parse_public_key(pk_bytes)?;
    let msg_h = bls_pop_message_hash(pk_bytes);
    signature::bls::BlsSmall::verify(&msg_h, pop, &vk)?;
    if let Ok(mut cache) = bls_pop_cache().lock() {
        cache.remember(Algorithm::BlsSmall, pk_bytes, pop);
    }
    Ok(())
}
/// Create BLS-Small Proof-of-Possession for the corresponding public key.
/// This signs `Hash(POP_DST` || `pk_bytes`) with the provided private key.
///
/// # Errors
/// Returns [`Error::BadSignature`] if the private key is not BLS-Small.
#[cfg(feature = "bls")]
pub fn bls_small_pop_prove(sk: &PrivateKey) -> Result<Vec<u8>, Error> {
    use crate::secrecy::ExposeSecret as _;
    match sk.0.expose_secret() {
        PrivateKeyInner::BlsSmall(_inner) => {
            let pk = PublicKey::from_private_key(sk)?;
            let pk_bytes = bls_public_key_payload(&pk, Algorithm::BlsSmall)?;
            let msg_h = bls_pop_message_hash(pk_bytes);
            signature::bls::BlsSmall::try_sign(
                &msg_h,
                match sk.0.expose_secret() {
                    PrivateKeyInner::BlsSmall(v) => v,
                    _ => unreachable!(),
                },
            )
        }
        _ => Err(Error::BadSignature),
    }
}
/// Aggregate-style check for Ed25519: per-signature verification wrapper.
/// # Errors
/// Returns `Err(Error::BadSignature)` if aggregate verification fails for any tuple or the input is empty.
pub fn ed25519_verify_aggregate(
    messages: &[&[u8]],
    signatures: &[&[u8]],
    public_keys: &[&[u8]],
) -> Result<(), Error> {
    ed25519_verify_batch_deterministic(messages, signatures, public_keys)
}
/// Aggregate-style check for ML-DSA-65: verifies each signature on the shared or unique message.
///
/// # Errors
/// Returns [`Error::BadSignature`] when the inputs are inconsistent or any signature fails verification.
pub fn pqc_verify_aggregate(
    messages: &[&[u8]],
    signatures: &[&[u8]],
    public_keys: &[&[u8]],
) -> Result<(), Error> {
    // ML-DSA has no standard aggregate signature; fall back to per-signature checks.
    if messages.is_empty()
        || !(messages.len() == signatures.len() && signatures.len() == public_keys.len())
    {
        return Err(Error::BadSignature);
    }
    for ((m, s), pk) in messages
        .iter()
        .zip(signatures.iter())
        .zip(public_keys.iter())
    {
        pqc_verify_batch_deterministic(
            core::slice::from_ref(m),
            core::slice::from_ref(s),
            core::slice::from_ref(pk),
            [0u8; 32],
        )?;
    }
    Ok(())
}
impl PublicKeyCompact {
    fn algorithm_tag(algorithm: Algorithm) -> u8 {
        match algorithm {
            Algorithm::Ed25519 => 0,
            Algorithm::Secp256k1 => 1,
            Algorithm::MlDsa => 4,
            #[cfg(feature = "gost")]
            Algorithm::Gost3410_2012_256ParamSetA => 5,
            #[cfg(feature = "gost")]
            Algorithm::Gost3410_2012_256ParamSetB => 6,
            #[cfg(feature = "gost")]
            Algorithm::Gost3410_2012_256ParamSetC => 7,
            #[cfg(feature = "gost")]
            Algorithm::Gost3410_2012_512ParamSetA => 8,
            #[cfg(feature = "gost")]
            Algorithm::Gost3410_2012_512ParamSetB => 9,
            #[cfg(feature = "bls")]
            Algorithm::BlsNormal => 2,
            #[cfg(feature = "bls")]
            Algorithm::BlsSmall => 3,
            #[cfg(feature = "sm")]
            Algorithm::Sm2 => 10,
        }
    }
    fn new(algorithm: Algorithm, payload: &[u8]) -> Self {
        // Use stable discriminants matching `Algorithm::try_from(u8)` below.
        let algorithm = Self::algorithm_tag(algorithm);
        let mut bytes = Vec::with_capacity(1 + payload.len());
        bytes.push(algorithm);
        bytes.extend_from_slice(payload);
        Self {
            algorithm_and_payload: ConstVec::new(bytes),
        }
    }
    fn try_algorithm(&self) -> Result<Algorithm, ParseError> {
        public_key_input::algorithm(&self.algorithm_and_payload)
            .map_err(PublicKeyEnvelopeError::into_parse_error)
    }
    fn try_payload(&self) -> Result<&[u8], ParseError> {
        public_key_input::payload(&self.algorithm_and_payload)
            .map_err(PublicKeyEnvelopeError::into_parse_error)
    }

    fn structural_components(&self) -> Result<(Algorithm, &[u8]), ParseError> {
        let algorithm = self.try_algorithm()?;
        let payload = self.try_payload()?;
        validate_public_key_structural_envelope(algorithm, payload)?;
        Ok((algorithm, payload))
    }
}
impl From<PublicKeyFull> for PublicKeyCompact {
    fn from(public_key: PublicKeyFull) -> Self {
        Self::new(public_key.algorithm(), &public_key.payload())
    }
}

impl norito::core::SerializePayload for PublicKeyCompact {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), norito::core::Error> {
        self.structural_components()
            .map_err(|_| norito::core::Error::Message("invalid public key".to_owned()))?;
        <ConstVec<u8> as norito::core::SerializePayload>::serialize(
            &self.algorithm_and_payload,
            writer,
        )
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        // `algorithm_and_payload` is private and every public constructor and
        // Norito decoder establishes its validity. Encoding and sizing are
        // therefore structural and never reparse cryptographic key material.
        self.structural_components().ok()?;
        <ConstVec<u8> as norito::core::SerializePayload>::encoded_len_hint(
            &self.algorithm_and_payload,
        )
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        self.structural_components().ok()?;
        <ConstVec<u8> as norito::core::SerializePayload>::encoded_len_exact(
            &self.algorithm_and_payload,
        )
    }
}

/// Public key used in signatures.
///
/// Its serialized form (via serde `Serialize`/`Deserialize`, plus [`Display`] and [`FromStr`]) is
/// represented as a [multihash](https://www.multiformats.io/multihash/) string.
/// [`FromStr`] also accepts an algorithm-prefixed form like
/// `"ed25519:<multihash-hex>"` for clarity in JSON. [`Display`] returns
/// the bare multihash hex. Multihash hex is canonical: varint bytes are
/// lowercase hex and payload bytes are uppercase hex; parsing rejects
/// non-canonical casing and `0x` prefixes.
/// For example:
///
/// ```
/// use iroha_crypto::{PublicKey, Algorithm};
///
/// let key = PublicKey::from_hex(
///     Algorithm::Ed25519,
///     "1509A611AD6D97B01D871E58ED00C8FD7C3917B6CA61A8C2833A19E000AAC2E4",
/// )
/// .unwrap();
///
/// assert_eq!(
///     format!("{key}"),
///     "ed01201509A611AD6D97B01D871E58ED00C8FD7C3917B6CA61A8C2833A19E000AAC2E4"
/// );
/// ```
#[derive(Clone, PartialEq, Eq, TypeId, norito::NoritoSchema)]
#[norito_schema(name = "iroha_crypto::PublicKey")]
#[repr(transparent)]
pub struct PublicKey(PublicKeyCompact);
impl PublicKey {
    fn new(inner: PublicKeyFull) -> Self {
        Self(inner.into())
    }
    /// Wipe the compact key bytes before discarding a confidential copy.
    ///
    /// The key intentionally becomes invalid and must not be used after this
    /// call. This is for restricted plaintext containers whose account or
    /// authorization identifiers are confidential even though public keys are
    /// not secrets in ordinary ledger state.
    pub fn zeroize_for_confidential_discard(&mut self) {
        self.0.zeroize();
    }
    /// Creates a new public key from raw bytes received from elsewhere.
    ///
    /// Ed25519 input must be a canonical encoding of a non-small-order point in the prime-order
    /// subgroup. This keeps every accepted account key in the same strict verification domain and
    /// rejects mixed-torsion encodings before they enter consensus state.
    ///
    /// # Errors
    ///
    /// Fails if public key parsing fails
    pub fn from_bytes(algorithm: Algorithm, payload: &[u8]) -> Result<Self, ParseError> {
        // Validate that `payload` is valid before constructing the key.
        parse_public_key_material(algorithm, payload).map(PublicKeyMaterial::into_public_key)
    }
    /// Derive a public key from private-key material.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeyGen`] when public-key derivation fails for algorithms
    /// whose private-key encodings contain consistency-checked public material.
    #[cfg_attr(
        not(any(feature = "pqc", feature = "gost", feature = "bls", feature = "sm")),
        expect(
            clippy::unnecessary_wraps,
            reason = "enabled algorithms require fallible derivation; reduced builds retain the same typed operation"
        )
    )]
    pub fn from_private_key(private_key: &PrivateKey) -> Result<Self, Error> {
        use crate::secrecy::ExposeSecret;
        let inner = match private_key.0.expose_secret() {
            PrivateKeyInner::Ed25519(secret) => PublicKeyFull::Ed25519(
                ed25519::Ed25519Sha512::keypair(KeyGenOption::FromPrivateKey(secret.clone())).0,
            ),
            PrivateKeyInner::Secp256k1(secret) => PublicKeyFull::Secp256k1(
                secp256k1::EcdsaSecp256k1Sha256::keypair(KeyGenOption::FromPrivateKey(
                    secret.clone(),
                ))
                .0,
            ),
            #[cfg(feature = "pqc")]
            PrivateKeyInner::MlDsa(secret) => {
                return mldsa_seed::mldsa65::public_key_from_secret(secret.as_secret());
            }
            #[cfg(feature = "gost")]
            PrivateKeyInner::Gost { algorithm, secret } => {
                let derived = signature::gost::derive_public_key(*algorithm, secret)
                    .map_err(|err| Error::KeyGen(err.to_string()))?;
                return Ok(Self(PublicKeyCompact::new(*algorithm, derived.as_bytes())));
            }
            #[cfg(feature = "bls")]
            PrivateKeyInner::BlsNormal(secret) => PublicKeyFull::from_bls_normal_key(
                bls::BlsNormal::derive_public_key(secret)
                    .map_err(|err| Error::KeyGen(err.to_string()))?,
            ),
            #[cfg(feature = "bls")]
            PrivateKeyInner::BlsSmall(secret) => PublicKeyFull::from_bls_small_key(
                &bls::BlsSmall::derive_public_key(secret)
                    .map_err(|err| Error::KeyGen(err.to_string()))?,
            ),
            #[cfg(feature = "sm")]
            PrivateKeyInner::Sm2(key) => {
                return key
                    .try_public_key()
                    .and_then(Sm2PublicKey::into_compact)
                    .map_err(|err| Error::KeyGen(err.to_string()));
            }
        };
        Ok(Self::new(inner))
    }
    /// Extracts raw bytes from the public key, copying the payload.
    ///
    /// `into_bytes()` without copying is not provided because underlying crypto
    /// libraries do not provide move functionality.
    pub fn to_bytes(&self) -> (Algorithm, &[u8]) {
        self.try_to_bytes().expect("Invalid PublicKey::to_bytes")
    }
    /// Construct from hex encoded string. A shorthand over [`Self::from_bytes`].
    ///
    /// # Errors
    ///
    /// - If the given payload is not hex encoded
    /// - If the given payload is not a valid private key
    pub fn from_hex(algorithm: Algorithm, payload: impl AsRef<str>) -> Result<Self, ParseError> {
        let payload = Zeroizing::new(hex_decode(payload.as_ref())?);
        Self::from_bytes(algorithm, payload.as_slice())
    }
    /// Fallibly get the digital signature algorithm of the public key.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] if the compact public-key state is missing its
    /// algorithm tag or contains an unknown tag.
    pub fn try_algorithm(&self) -> Result<Algorithm, ParseError> {
        self.0.try_algorithm()
    }
    /// Get the digital signature algorithm of the public key.
    ///
    /// # Panics
    ///
    /// Panics if the compact public-key state is malformed. Use
    /// [`Self::try_algorithm`] in fallible paths.
    pub fn algorithm(&self) -> Algorithm {
        self.try_algorithm().expect("Invalid PublicKey::algorithm")
    }
}

impl Zeroize for PublicKey {
    fn zeroize(&mut self) {
        self.zeroize_for_confidential_discard();
    }
}
impl PublicKey {
    /// Fallibly clone a previously validated compact key for an admitted
    /// ownership boundary without consulting backend parse caches.
    ///
    /// # Errors
    ///
    /// Returns a decode-resource or allocation error if the exact compact
    /// destination cannot be admitted.
    #[doc(hidden)]
    pub fn try_clone_for_admission(&self) -> Result<Self, norito::core::Error> {
        let (algorithm, payload) = self
            .structural_components()
            .map_err(|_| norito::core::Error::Message("invalid public key".to_owned()))?;
        PublicKeyCompact::try_new_for_decode(algorithm, payload).map(Self)
    }

    fn structural_components(&self) -> Result<(Algorithm, &[u8]), ParseError> {
        self.0.structural_components()
    }

    /// Format as a canonical bare multihash hex string.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] if the public-key payload cannot be encoded as a
    /// canonical multihash string.
    pub fn try_to_multihash_string(&self) -> Result<String, ParseError> {
        // Public constructors and decoders establish the compact-key
        // invariant. Formatting can therefore use the retained canonical
        // bytes directly without consulting algorithm-specific parse caches.
        let (algorithm, payload) = self.structural_components()?;
        let digest_function = multihash::public_key_digest_function(algorithm);
        let output_len = canonical_public_key_multihash_hex_len(digest_function, payload.len())
            .ok_or_else(|| ParseError("public-key multihash length overflow".to_owned()))?;
        let mut output = String::new();
        output
            .try_reserve_exact(output_len)
            .map_err(|_| ParseError("failed to allocate public-key multihash".to_owned()))?;
        push_lower_varint_hex(digest_function, &mut output);
        push_lower_varint_hex(payload.len() as u64, &mut output);
        for byte in payload {
            push_string_hex_byte(*byte, b"0123456789ABCDEF", &mut output);
        }
        debug_assert_eq!(output.len(), output_len);
        Ok(output)
    }
    fn malformed_compact_marker(&self) -> String {
        format!(
            "invalid-public-key:{}",
            hex::encode(self.0.algorithm_and_payload.as_ref())
        )
    }
    fn normalize_lossy(&self) -> String {
        self.try_to_multihash_string()
            .unwrap_or_else(|_| self.malformed_compact_marker())
    }
    /// Fallibly format as an algorithm-prefixed multihash string (e.g., "ed25519:...").
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] if the public-key payload cannot be encoded as a
    /// canonical multihash string.
    pub fn try_to_prefixed_string(&self) -> Result<String, ParseError> {
        let (algorithm, payload) = self.structural_components()?;
        Ok(multihash::encode_public_key_prefixed(algorithm, payload))
    }
    /// Format as an algorithm-prefixed multihash string (e.g., "ed25519:...").
    pub fn to_prefixed_string(&self) -> String {
        self.try_to_prefixed_string()
            .unwrap_or_else(|_| self.malformed_compact_marker())
    }
}

fn canonical_public_key_multihash_hex_len(
    mut digest_function: u64,
    payload_len: usize,
) -> Option<usize> {
    let mut header_bytes = 1_usize;
    while digest_function >= 0x80 {
        digest_function >>= 7;
        header_bytes = header_bytes.checked_add(1)?;
    }
    let mut encoded_len = u64::try_from(payload_len).ok()?;
    header_bytes = header_bytes.checked_add(1)?;
    while encoded_len >= 0x80 {
        encoded_len >>= 7;
        header_bytes = header_bytes.checked_add(1)?;
    }
    header_bytes
        .checked_add(payload_len)
        .and_then(|bytes| bytes.checked_mul(2))
}

fn push_lower_varint_hex(mut value: u64, output: &mut String) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        push_string_hex_byte(byte, b"0123456789abcdef", output);
        if value == 0 {
            return;
        }
    }
}

fn push_string_hex_byte(byte: u8, alphabet: &[u8; 16], output: &mut String) {
    output.push(char::from(alphabet[usize::from(byte >> 4)]));
    output.push(char::from(alphabet[usize::from(byte & 0x0f)]));
}
impl core::hash::Hash for PublicKey {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        match self.try_to_bytes() {
            Ok(bytes) => bytes.hash(state),
            Err(_) => self.0.algorithm_and_payload.hash(state),
        }
    }
}
impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for PublicKey {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        match (self.try_to_bytes(), other.try_to_bytes()) {
            (Ok(left), Ok(right)) => left.cmp(&right),
            (Err(_), Err(_)) => self
                .0
                .algorithm_and_payload
                .cmp(&other.0.algorithm_and_payload),
            (Ok(_), Err(_)) => core::cmp::Ordering::Less,
            (Err(_), Ok(_)) => core::cmp::Ordering::Greater,
        }
    }
}
// Bridge Norito slice-based decoding for PublicKey to the codec decoder.
// This allows containers (Vec/Option) using PublicKey elements to decode via
// `norito::core::DecodeFromSlice` without re-implementing deep decoders.
impl<'a> norito::core::DecodeFromSlice<'a> for PublicKey {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        <PublicKeyCompact as norito::core::DecodeFromSlice>::decode_from_slice(bytes)
            .map(|(compact, used)| (Self(compact), used))
    }
}
impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // This could be simplified using `f.field_with` when `debug_closure_helpers` feature become stable
        struct Helper {
            algorithm: Algorithm,
            normalized: String,
        }
        impl fmt::Debug for Helper {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_tuple(self.algorithm.as_static_str())
                    .field(&self.normalized)
                    .finish()
            }
        }
        match self.try_algorithm() {
            Ok(algorithm) => {
                let helper = Helper {
                    algorithm,
                    normalized: self.normalize_lossy(),
                };
                f.debug_tuple("PublicKey").field(&helper).finish()
            }
            Err(err) => f
                .debug_struct("PublicKey")
                .field("invalid", &err.to_string())
                .field(
                    "raw_compact",
                    &hex::encode(self.0.algorithm_and_payload.as_ref()),
                )
                .finish(),
        }
    }
}
impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Ok((algorithm, payload)) = self.structural_components() {
            fmt_lower_varint_hex(multihash::public_key_digest_function(algorithm), f)?;
            fmt_lower_varint_hex(payload.len() as u64, f)?;
            for byte in payload {
                write!(f, "{byte:02X}")?;
            }
            Ok(())
        } else {
            f.write_str("invalid-public-key:")?;
            for byte in self.0.algorithm_and_payload.as_ref() {
                write!(f, "{byte:02x}")?;
            }
            Ok(())
        }
    }
}

fn fmt_lower_varint_hex(mut value: u64, output: &mut fmt::Formatter<'_>) -> fmt::Result {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        write!(output, "{byte:02x}")?;
        if value == 0 {
            return Ok(());
        }
    }
}
impl norito::json::JsonSerialize for PublicKey {
    fn json_serialize(&self, out: &mut String) {
        let normalized = self.normalize_lossy();
        norito::json::JsonSerialize::json_serialize(&normalized, out);
    }
    fn json_serialize_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        let (algorithm, payload) = self
            .structural_components()
            .map_err(|_| norito::json::BoundedJsonError::Unsupported)?;
        out.push('"')?;
        write_lower_varint_hex(multihash::public_key_digest_function(algorithm), out)?;
        write_lower_varint_hex(payload.len() as u64, out)?;
        for byte in payload {
            write_hex_byte(*byte, b"0123456789ABCDEF", out)?;
        }
        out.push('"')
    }
}
impl norito::json::JsonDeserialize for PublicKey {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        let value: String = norito::json::JsonDeserialize::json_deserialize(parser)?;
        Self::from_canonical_str_for_decode(&value).map_err(public_key_json_decode_error)
    }

    fn json_from_value(value: &norito::json::Value) -> Result<Self, norito::json::Error> {
        let norito::json::Value::String(value) = value else {
            return Err(norito::json::Error::Message(
                "invalid public key".to_owned(),
            ));
        };
        Self::from_canonical_str_for_decode(value).map_err(public_key_json_decode_error)
    }
}
impl norito::json::JsonObjectKey for PublicKey {
    fn visit_json_key_text<E>(
        &self,
        mut visitor: impl FnMut(&str) -> Result<(), E>,
    ) -> Result<(), E> {
        let canonical = self.normalize_lossy();
        visitor(&canonical)
    }

    fn visit_json_key_text_checked(
        &self,
        visitor: impl FnMut(&str) -> Result<(), norito::json::BoundedJsonError>,
    ) -> Result<(), norito::json::BoundedJsonError> {
        self.structural_components()
            .map_err(|_| norito::json::BoundedJsonError::Unsupported)?;
        norito::json::visit_json_display_text(self, visitor)
    }
}
impl norito::json::JsonObjectKeyOwned for PublicKey {
    fn from_json_key_text(key: &str) -> Result<Self, norito::json::Error> {
        Self::from_canonical_str_for_decode(key).map_err(public_key_json_decode_error)
    }
}

fn public_key_json_decode_error(error: norito::core::Error) -> norito::json::Error {
    if error.is_decode_resource_limit() {
        norito::json::Error::from_decode_resource(error)
    } else {
        norito::json::Error::Message("invalid public key".to_owned())
    }
}
fn write_lower_varint_hex(
    mut value: u64,
    out: &mut dyn norito::json::JsonWriteSink,
) -> Result<(), norito::json::BoundedJsonError> {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        write_hex_byte(byte, b"0123456789abcdef", out)?;
        if value == 0 {
            return Ok(());
        }
    }
}
fn write_hex_byte(
    byte: u8,
    alphabet: &[u8; 16],
    out: &mut dyn norito::json::JsonWriteSink,
) -> Result<(), norito::json::BoundedJsonError> {
    out.push(char::from(alphabet[usize::from(byte >> 4)]))?;
    out.push(char::from(alphabet[usize::from(byte & 0x0f)]))
}
impl norito::json::JsonDeserialize for PrivateKey {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        let value: String = norito::json::JsonDeserialize::json_deserialize(parser)?;
        value
            .parse()
            .map_err(|err: ParseError| norito::json::Error::Message(err.to_string()))
    }
}
impl FromStr for PublicKey {
    type Err = ParseError;
    fn from_str(key: &str) -> Result<Self, Self::Err> {
        let (algorithm, payload) = multihash::decode_public_key_str(key)?;
        Self::from_bytes(algorithm, &payload)
    }
}

impl norito::core::SerializePayload for PublicKey {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), norito::core::Error> {
        norito::core::SerializePayload::serialize(&self.0, writer)
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        // See `PublicKeyCompact`: the private invariant makes both sizing and
        // serialization structural and free of cryptographic reparsing.
        norito::core::SerializePayload::encoded_len_hint(&self.0)
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        norito::core::SerializePayload::encoded_len_exact(&self.0)
    }
}

impl<'de> norito::core::DeserializePayload<'de> for PublicKey {
    fn deserialize(archived: &'de norito::core::Archived<Self>) -> Self {
        Self::try_deserialize(archived).expect("PublicKey decode")
    }
    fn try_deserialize(
        archived: &'de norito::core::Archived<Self>,
    ) -> Result<Self, norito::core::Error> {
        let archived_compact = archived.cast::<PublicKeyCompact>();
        PublicKeyCompact::try_deserialize(archived_compact).map(Self)
    }
}
impl IntoSchema for PublicKey {
    fn type_name() -> String {
        Self::id()
    }
    fn update_schema_map(metamap: &mut MetaMap) {
        if !metamap.contains_key::<Self>() {
            if !metamap.contains_key::<Algorithm>() {
                <Algorithm as iroha_schema::IntoSchema>::update_schema_map(metamap);
            }
            if !metamap.contains_key::<ConstVec<u8>>() {
                <ConstVec<u8> as iroha_schema::IntoSchema>::update_schema_map(metamap);
            }
            metamap.insert::<Self>(Metadata::Struct(NamedFieldsMeta {
                declarations: vec![
                    Declaration {
                        name: String::from("algorithm"),
                        ty: core::any::TypeId::of::<Algorithm>(),
                    },
                    Declaration {
                        name: String::from("payload"),
                        ty: core::any::TypeId::of::<ConstVec<u8>>(),
                    },
                ],
            }));
        }
    }
}
impl From<PrivateKey> for PublicKey {
    fn from(private_key: PrivateKey) -> Self {
        Self::from_private_key(&private_key)
            .expect("deriving a public key from a private key should succeed for valid keys")
    }
}
#[derive(Clone)]
#[cfg(feature = "pqc")]
struct MlDsaSecretKey {
    inner: Arc<MlDsaSecretKeyInner>,
}
#[cfg(feature = "pqc")]
struct MlDsaSecretKeyInner {
    secret: pqcrypto_mldsa::mldsa65::SecretKey,
}
#[cfg(feature = "pqc")]
impl MlDsaSecretKey {
    fn new(inner: &pqcrypto_mldsa::mldsa65::SecretKey) -> Self {
        Self {
            inner: Arc::new(MlDsaSecretKeyInner { secret: *inner }),
        }
    }
    fn from_bytes(bytes: &[u8]) -> Result<Self, ParseError> {
        use pqcrypto_traits::sign::SecretKey as _;
        soranet_pq::validate_mldsa_secret_key(soranet_pq::MlDsaSuite::MlDsa65, bytes)
            .map_err(|err| ParseError(err.to_string()))?;
        let mut inner = pqcrypto_mldsa::mldsa65::SecretKey::from_bytes(bytes)
            .map_err(|err| ParseError(err.to_string()))?;
        let secret = Self::new(&inner);
        zeroize_mldsa_secret_key(&mut inner);
        Ok(secret)
    }
    fn as_secret(&self) -> &pqcrypto_mldsa::mldsa65::SecretKey {
        &self.inner.secret
    }
    fn to_vec(&self) -> Vec<u8> {
        use pqcrypto_traits::sign::SecretKey as _;
        self.inner.secret.as_bytes().to_vec()
    }
    fn try_sign(&self, payload: &[u8]) -> Result<Vec<u8>, Error> {
        self.try_sign_with_context(&[], payload)
    }
    fn try_sign_with_context(&self, context: &[u8], payload: &[u8]) -> Result<Vec<u8>, Error> {
        let mut rng = rand::rngs::OsRng;
        self.try_sign_with_context_and_rng(context, payload, &mut rng)
    }
    #[cfg(test)]
    fn try_sign_with_rng<R: rand_core::TryCryptoRng + ?Sized>(
        &self,
        payload: &[u8],
        rng: &mut R,
    ) -> Result<Vec<u8>, Error> {
        self.try_sign_with_context_and_rng(&[], payload, rng)
    }
    fn try_sign_with_context_and_rng<R: rand_core::TryCryptoRng + ?Sized>(
        &self,
        context: &[u8],
        payload: &[u8],
        rng: &mut R,
    ) -> Result<Vec<u8>, Error> {
        use pqcrypto_traits::sign::SecretKey as _;
        mldsa_seed::mldsa65::public_key_from_secret(self.as_secret())
            .map_err(|err| Error::Signing(err.to_string()))?;
        soranet_pq::sign_mldsa_from_rng(
            soranet_pq::MlDsaSuite::MlDsa65,
            self.as_secret().as_bytes(),
            context,
            payload,
            rng,
        )
        .map(soranet_pq::MlDsaSignature::into_bytes)
        .map_err(|err| Error::Signing(err.to_string()))
    }
    fn try_sign_with_context_and_hedged_rng(
        &self,
        context: &[u8],
        payload: &[u8],
        rng: &mut soranet_pq::HedgedChaCha20Rng,
    ) -> Result<Vec<u8>, Error> {
        use pqcrypto_traits::sign::SecretKey as _;
        mldsa_seed::mldsa65::public_key_from_secret(self.as_secret())
            .map_err(|err| Error::Signing(err.to_string()))?;
        soranet_pq::sign_mldsa(
            soranet_pq::MlDsaSuite::MlDsa65,
            self.as_secret().as_bytes(),
            context,
            payload,
            rng,
        )
        .map(soranet_pq::MlDsaSignature::into_bytes)
        .map_err(|err| Error::Signing(err.to_string()))
    }
    #[cfg(test)]
    fn strong_count(&self) -> usize {
        Arc::strong_count(&self.inner)
    }
}
#[cfg(feature = "pqc")]
impl PartialEq for MlDsaSecretKey {
    fn eq(&self, other: &Self) -> bool {
        use pqcrypto_traits::sign::SecretKey as _;
        self.inner.secret.as_bytes() == other.inner.secret.as_bytes()
    }
}
#[cfg(feature = "pqc")]
impl Eq for MlDsaSecretKey {}
#[cfg(feature = "pqc")]
impl ZeroizeOnDrop for MlDsaSecretKey {}
#[cfg(feature = "pqc")]
#[allow(unsafe_code)]
fn zeroize_mldsa_secret_key(secret: &mut pqcrypto_mldsa::mldsa65::SecretKey) {
    use core::{mem, ptr, slice};
    let byte_ptr = ptr::addr_of_mut!(*secret).cast::<u8>();
    // SAFETY: `byte_ptr` points to the complete live `SecretKey` object. The
    // upstream type is a plain fixed-size byte wrapper; treating its object
    // representation as bytes is the same layout assumption required to hold
    // the key at all. `Zeroize` uses volatile stores plus a compiler fence, so
    // the erase cannot be removed merely because the object is about to drop.
    let bytes = unsafe {
        slice::from_raw_parts_mut(
            byte_ptr,
            mem::size_of::<pqcrypto_mldsa::mldsa65::SecretKey>(),
        )
    };
    zeroize::Zeroize::zeroize(bytes);
}
#[cfg(feature = "pqc")]
impl Drop for MlDsaSecretKeyInner {
    fn drop(&mut self) {
        zeroize_mldsa_secret_key(&mut self.secret);
    }
}
#[derive(Clone)]
#[allow(variant_size_differences, clippy::large_enum_variant)]
enum PrivateKeyInner {
    Ed25519(ed25519::PrivateKey),
    Secp256k1(secp256k1::PrivateKey),
    #[cfg(feature = "pqc")]
    MlDsa(MlDsaSecretKey),
    #[cfg(feature = "gost")]
    Gost {
        algorithm: Algorithm,
        secret: signature::gost::PrivateKey,
    },
    #[cfg(feature = "sm")]
    Sm2(sm::Sm2PrivateKey),
    #[cfg(feature = "bls")]
    BlsNormal(bls::BlsNormalPrivateKey),
    #[cfg(feature = "bls")]
    BlsSmall(bls::BlsSmallPrivateKey),
}
/// Private Key used in signatures.
#[derive(Clone)]
#[allow(variant_size_differences)]
pub struct PrivateKey(Box<Secret<PrivateKeyInner>>);
#[allow(unsafe_code)]
unsafe impl Send for PrivateKey {}
#[allow(unsafe_code)]
unsafe impl Sync for PrivateKey {}
impl PartialEq for PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        use crate::secrecy::ExposeSecret;
        #[cfg(feature = "bls")]
        use subtle::ConstantTimeEq as _;
        match (self.0.expose_secret(), other.0.expose_secret()) {
            (PrivateKeyInner::Ed25519(l), PrivateKeyInner::Ed25519(r)) => l == r,
            (PrivateKeyInner::Secp256k1(l), PrivateKeyInner::Secp256k1(r)) => l == r,
            #[cfg(feature = "pqc")]
            (PrivateKeyInner::MlDsa(l), PrivateKeyInner::MlDsa(r)) => l == r,
            #[cfg(feature = "gost")]
            (
                PrivateKeyInner::Gost {
                    algorithm: la,
                    secret: ls,
                },
                PrivateKeyInner::Gost {
                    algorithm: ra,
                    secret: rs,
                },
            ) => la == ra && ls == rs,
            #[cfg(feature = "bls")]
            (PrivateKeyInner::BlsNormal(l), PrivateKeyInner::BlsNormal(r)) => {
                bool::from(l.as_bytes().ct_eq(r.as_bytes()))
            }
            #[cfg(feature = "bls")]
            (PrivateKeyInner::BlsSmall(l), PrivateKeyInner::BlsSmall(r)) => {
                bool::from(l.as_bytes().ct_eq(r.as_bytes()))
            }
            #[cfg(feature = "sm")]
            (PrivateKeyInner::Sm2(l), PrivateKeyInner::Sm2(r)) => l == r,
            _ => false,
        }
    }
}
impl Eq for PrivateKey {}
fn zeroizing_secret_bytes_to_vec<T>(bytes: T) -> Vec<u8>
where
    T: AsRef<[u8]> + Zeroize,
{
    let bytes = Zeroizing::new(bytes);
    bytes.as_ref().to_vec()
}
impl PrivateKey {
    /// Creates a new public key from raw bytes received from elsewhere
    ///
    /// # Errors
    ///
    /// - If the given payload is not a valid private key for the given digest function
    pub fn from_bytes(algorithm: Algorithm, payload: &[u8]) -> Result<Self, ParseError> {
        match algorithm {
            Algorithm::Ed25519 => {
                ed25519::Ed25519Sha512::parse_private_key(payload).map(PrivateKeyInner::Ed25519)
            }
            Algorithm::Secp256k1 => secp256k1::EcdsaSecp256k1Sha256::parse_private_key(payload)
                .map(PrivateKeyInner::Secp256k1),
            #[cfg(feature = "pqc")]
            Algorithm::MlDsa => MlDsaSecretKey::from_bytes(payload).and_then(|secret| {
                mldsa_seed::mldsa65::public_key_from_secret(secret.as_secret())
                    .map_err(|err| ParseError(err.to_string()))?;
                Ok(PrivateKeyInner::MlDsa(secret))
            }),
            #[cfg(not(feature = "pqc"))]
            Algorithm::MlDsa => Err(ParseError(String::from(
                "ML-DSA backend is unavailable on this target",
            ))),
            #[cfg(feature = "gost")]
            Algorithm::Gost3410_2012_256ParamSetA
            | Algorithm::Gost3410_2012_256ParamSetB
            | Algorithm::Gost3410_2012_256ParamSetC
            | Algorithm::Gost3410_2012_512ParamSetA
            | Algorithm::Gost3410_2012_512ParamSetB => {
                signature::gost::parse_private_key(algorithm, payload)
                    .map(|secret| PrivateKeyInner::Gost { algorithm, secret })
            }
            #[cfg(feature = "sm")]
            Algorithm::Sm2 => sm::decode_sm2_private_key_payload(payload).map(PrivateKeyInner::Sm2),
            #[cfg(feature = "bls")]
            Algorithm::BlsNormal => {
                bls::BlsNormal::parse_private_key(payload).map(PrivateKeyInner::BlsNormal)
            }
            #[cfg(feature = "bls")]
            Algorithm::BlsSmall => {
                bls::BlsSmall::parse_private_key(payload).map(PrivateKeyInner::BlsSmall)
            }
        }
        .map(Secret::new)
        .map(Box::new)
        .map(PrivateKey)
    }
    /// Construct [`PrivateKey`] from hex encoded string.
    /// A shorthand over [`PrivateKey::from_bytes`]
    ///
    /// # Errors
    ///
    /// - If the given payload is not hex encoded
    /// - If the given payload is not a valid private key
    pub fn from_hex(algorithm: Algorithm, payload: impl AsRef<str>) -> Result<Self, ParseError> {
        let payload = Zeroizing::new(hex_decode(payload.as_ref())?);
        Self::from_bytes(algorithm, payload.as_slice())
    }
    /// Get the digital signature algorithm of the private key
    pub fn algorithm(&self) -> Algorithm {
        use crate::secrecy::ExposeSecret;
        match self.0.expose_secret() {
            PrivateKeyInner::Ed25519(_) => Algorithm::Ed25519,
            PrivateKeyInner::Secp256k1(_) => Algorithm::Secp256k1,
            #[cfg(feature = "pqc")]
            PrivateKeyInner::MlDsa(_) => Algorithm::MlDsa,
            #[cfg(feature = "gost")]
            PrivateKeyInner::Gost { algorithm, .. } => *algorithm,
            #[cfg(feature = "sm")]
            PrivateKeyInner::Sm2(_) => Algorithm::Sm2,
            #[cfg(feature = "bls")]
            PrivateKeyInner::BlsNormal(_) => Algorithm::BlsNormal,
            #[cfg(feature = "bls")]
            PrivateKeyInner::BlsSmall(_) => Algorithm::BlsSmall,
        }
    }
    /// Fallibly extract the private-key payload.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] if an algorithm-specific private-key envelope
    /// cannot be encoded.
    // SM2 payload encoding is fallible under `feature = "sm"`; keep one
    // feature-independent signature for callers that canonicalize private keys.
    #[allow(clippy::unnecessary_wraps)]
    pub fn try_payload(&self) -> Result<Vec<u8>, ParseError> {
        use crate::secrecy::ExposeSecret;
        let payload = match self.0.expose_secret() {
            PrivateKeyInner::Ed25519(key) => zeroizing_secret_bytes_to_vec(key.to_bytes()),
            PrivateKeyInner::Secp256k1(key) => zeroizing_secret_bytes_to_vec(key.to_bytes()),
            #[cfg(feature = "pqc")]
            PrivateKeyInner::MlDsa(key) => key.to_vec(),
            #[cfg(feature = "gost")]
            PrivateKeyInner::Gost { secret, .. } => secret.as_bytes().to_vec(),
            #[cfg(feature = "sm")]
            PrivateKeyInner::Sm2(key) => {
                let secret = Zeroizing::new(key.secret_bytes());
                sm::encode_sm2_private_key_payload(key.distid(), secret.as_slice())?
            }
            #[cfg(feature = "bls")]
            PrivateKeyInner::BlsNormal(key) => key.as_bytes().to_vec(),
            #[cfg(feature = "bls")]
            PrivateKeyInner::BlsSmall(key) => key.as_bytes().to_vec(),
        };
        Ok(payload)
    }
    /// Extracts the raw bytes from the private key, copying the payload.
    ///
    /// `into_bytes()` without copying is not provided because underlying crypto
    /// libraries do not provide move functionality.
    pub fn to_bytes(&self) -> (Algorithm, Vec<u8>) {
        self.try_to_bytes()
            .expect("validated private-key payload should export")
    }
    /// Fallibly extract the signature algorithm and raw private-key payload.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] if an algorithm-specific private-key envelope
    /// cannot be encoded.
    pub fn try_to_bytes(&self) -> Result<(Algorithm, Vec<u8>), ParseError> {
        Ok((self.algorithm(), self.try_payload()?))
    }
}
impl norito::json::JsonDeserialize for KeyPair {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        let mut map = norito::json::MapVisitor::new(parser)?;
        let mut public_key: Option<PublicKey> = None;
        let mut private_key: Option<ExposedPrivateKey> = None;
        while let Some(field) = map.next_key()? {
            match field.as_str() {
                "public_key" => {
                    if public_key.is_some() {
                        return Err(norito::json::MapVisitor::duplicate_field("public_key"));
                    }
                    public_key = Some(map.parse_value()?);
                }
                "private_key" => {
                    if private_key.is_some() {
                        return Err(norito::json::MapVisitor::duplicate_field("private_key"));
                    }
                    private_key = Some(map.parse_value()?);
                }
                _ => map.skip_value()?,
            }
        }
        map.finish()?;
        let public_key =
            public_key.ok_or_else(|| norito::json::MapVisitor::missing_field("public_key"))?;
        let exposed =
            private_key.ok_or_else(|| norito::json::MapVisitor::missing_field("private_key"))?;
        KeyPair::new(public_key, exposed.0.clone())
            .map_err(|err| norito::json::Error::Message(err.to_string()))
    }
}
impl norito::json::JsonSerialize for KeyPair {
    fn json_serialize(&self, out: &mut String) {
        use norito::json::{self, Value};
        let mut map = norito::json::Map::new();
        map.insert(
            "public_key".into(),
            json::to_value(&self.public_key).expect("serialize public key"),
        );
        map.insert(
            "private_key".into(),
            json::to_value(&self.private_key).expect("serialize private key"),
        );
        json::JsonSerialize::json_serialize(&Value::Object(map), out);
    }
    fn json_serialize_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        out.begin_container()?;
        let result = (|| -> Result<(), norito::json::BoundedJsonError> {
            // The legacy `Value::Object` path is a `BTreeMap`, so preserve its
            // lexicographic key order exactly.
            out.push_str("{\"private_key\":")?;
            norito::json::JsonSerialize::json_serialize_to(&self.private_key, out)?;
            out.push_str(",\"public_key\":")?;
            norito::json::JsonSerialize::json_serialize_to(&self.public_key, out)?;
            out.push('}')?;
            Ok(())
        })();
        out.end_container();
        result
    }
}
impl FromStr for PrivateKey {
    type Err = ParseError;
    fn from_str(key: &str) -> Result<Self, Self::Err> {
        let (algorithm, payload) = multihash::decode_private_key_str(key)?;
        let payload = Zeroizing::new(payload);
        PrivateKey::from_bytes(algorithm, payload.as_slice())
    }
}
impl ZeroizeOnDrop for PrivateKeyInner {}
impl Drop for PrivateKeyInner {
    fn drop(&mut self) {
        fn assert_will_zeroize_on_drop(_value: &mut impl ZeroizeOnDrop) {
            // checks that `zeroize` feature of `ed25519-dalek` crate is enabled
            // actual zeroize will be in `impl Drop` for nested key
        }
        match self {
            PrivateKeyInner::Ed25519(key) => {
                assert_will_zeroize_on_drop(key);
            }
            PrivateKeyInner::Secp256k1(key) => {
                assert_will_zeroize_on_drop(key);
            }
            #[cfg(feature = "pqc")]
            PrivateKeyInner::MlDsa(key) => {
                assert_will_zeroize_on_drop(key);
            }
            #[cfg(feature = "gost")]
            PrivateKeyInner::Gost { secret, .. } => {
                assert_will_zeroize_on_drop(secret);
            }
            #[cfg(feature = "sm")]
            PrivateKeyInner::Sm2(key) => {
                assert_will_zeroize_on_drop(key);
            }
            #[cfg(feature = "bls")]
            PrivateKeyInner::BlsNormal(key) => {
                key.zeroize();
            }
            #[cfg(feature = "bls")]
            PrivateKeyInner::BlsSmall(key) => {
                key.zeroize();
            }
        }
    }
}
const PRIVATE_KEY_REDACTED: &str = "[REDACTED PrivateKey]";
impl core::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        PRIVATE_KEY_REDACTED.fmt(f)
    }
}
impl core::fmt::Display for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        PRIVATE_KEY_REDACTED.fmt(f)
    }
}
impl norito::json::JsonSerialize for PrivateKey {
    fn json_serialize(&self, out: &mut String) {
        let redacted = PRIVATE_KEY_REDACTED.to_string();
        norito::json::JsonSerialize::json_serialize(&redacted, out);
    }
    fn json_serialize_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        norito::json::write_json_string_to(PRIVATE_KEY_REDACTED, out)
    }
}
/// Explicit wrapper for formatting or serializing private-key material (for example, in kagami).
///
/// [`FromStr`] accepts both a bare multihash hex string and an algorithm-prefixed
/// variant such as `"ml-dsa:<multihash-hex>"`. The default [`Display`] formatting returns
/// the bare multihash hex. Multihash hex is canonical: varint bytes are lowercase hex
/// and payload bytes are uppercase hex; parsing rejects non-canonical casing and
/// `0x` prefixes.
///
/// [`Debug`] is always redacted so that embedding this type in another debug-formatted
/// value cannot disclose key material. [`Display`], JSON/Norito serialization, and the
/// named export methods expose the private key deliberately and must not be used in logs.
#[derive(Clone, Eq, PartialEq, norito::NoritoSchema)]
#[norito_schema(name = "iroha_crypto::ExposedPrivateKey")]
pub struct ExposedPrivateKey(pub PrivateKey);
impl FromStr for ExposedPrivateKey {
    type Err = ParseError;
    fn from_str(key: &str) -> Result<Self, Self::Err> {
        let private_key = key.parse()?;
        Ok(ExposedPrivateKey(private_key))
    }
}
impl ExposedPrivateKey {
    fn malformed_private_key_marker(&self) -> String {
        format!("invalid-private-key:{}", self.0.algorithm().as_static_str())
    }
    /// Format as a canonical bare private-key multihash hex string.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] if the private-key payload cannot be encoded as a
    /// canonical multihash string.
    pub fn try_to_multihash_string(&self) -> Result<String, ParseError> {
        let (algorithm, payload) = self.0.try_to_bytes()?;
        let payload = Zeroizing::new(payload);
        Ok(multihash::encode_private_key_string(
            algorithm,
            payload.as_slice(),
        ))
    }
    fn normalize(&self) -> String {
        self.try_to_multihash_string()
            .unwrap_or_else(|_| self.malformed_private_key_marker())
    }
    /// Fallibly format as an algorithm-prefixed multihash string (e.g., "ml-dsa:...").
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] if the private-key payload cannot be encoded as a
    /// canonical multihash string.
    pub fn try_to_prefixed_string(&self) -> Result<String, ParseError> {
        let (algorithm, payload) = self.0.try_to_bytes()?;
        let payload = Zeroizing::new(payload);
        Ok(multihash::encode_private_key_prefixed(
            algorithm,
            payload.as_slice(),
        ))
    }
    /// Format as an algorithm-prefixed multihash string (e.g., "ml-dsa:...").
    pub fn to_prefixed_string(&self) -> String {
        self.try_to_prefixed_string()
            .unwrap_or_else(|_| self.malformed_private_key_marker())
    }
}
impl fmt::Debug for ExposedPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExposedPrivateKey")
            .field("algorithm", &self.0.algorithm())
            .field("private_key", &self.0)
            .finish()
    }
}
impl norito::json::JsonSerialize for ExposedPrivateKey {
    fn json_serialize(&self, out: &mut String) {
        let normalized = self.normalize();
        norito::json::JsonSerialize::json_serialize(&normalized, out);
    }
    fn json_serialize_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        norito::json::write_json_string_to(&self.normalize(), out)
    }
}
impl norito::json::JsonDeserialize for ExposedPrivateKey {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        let value: String = norito::json::JsonDeserialize::json_deserialize(parser)?;
        value
            .parse::<ExposedPrivateKey>()
            .map_err(|err| norito::json::Error::Message(err.to_string()))
    }
}

impl norito::core::SerializePayload for ExposedPrivateKey {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), norito::core::Error> {
        let normalized = self.normalize();
        norito::core::SerializePayload::serialize(&normalized, writer)
    }
}

impl<'de> norito::core::DeserializePayload<'de> for ExposedPrivateKey {
    fn deserialize(archived: &'de norito::core::Archived<ExposedPrivateKey>) -> Self {
        Self::try_deserialize(archived).expect("ExposedPrivateKey normalization")
    }
    fn try_deserialize(
        archived: &'de norito::core::Archived<ExposedPrivateKey>,
    ) -> Result<Self, norito::core::Error> {
        let archived_str: &norito::core::Archived<String> = archived.cast();
        let raw = <String as norito::core::DeserializePayload>::try_deserialize(archived_str)?;
        raw.parse::<ExposedPrivateKey>()
            .map_err(|err| norito::core::Error::Message(err.to_string()))
    }
}
impl fmt::Display for ExposedPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.normalize())
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct ZeroizingConstVec(ConstVec<u8>);
impl ZeroizingConstVec {
    fn new(bytes: Vec<u8>) -> Self {
        Self(ConstVec::from(bytes))
    }
    fn as_slice(&self) -> &[u8] {
        self.0.as_ref()
    }
}
impl Zeroize for ZeroizingConstVec {
    fn zeroize(&mut self) {
        let mut bytes = core::mem::take(&mut self.0).into_vec();
        let len = bytes.len();
        bytes.zeroize();
        bytes.resize(len, 0);
        record_session_key_zeroization(&bytes);
        self.0 = ConstVec::from(bytes);
    }
}
impl ZeroizeOnDrop for ZeroizingConstVec {}
impl Drop for ZeroizingConstVec {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl AsRef<[u8]> for ZeroizingConstVec {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}
fn session_key_zeroization_log() -> &'static std::sync::Mutex<Vec<u8>> {
    use std::sync::{Mutex, OnceLock};
    static LOG: OnceLock<Mutex<Vec<u8>>> = OnceLock::new();
    LOG.get_or_init(|| Mutex::new(Vec::new()))
}
fn session_key_zeroization_guard() -> std::sync::MutexGuard<'static, Vec<u8>> {
    session_key_zeroization_log()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
fn record_session_key_zeroization(bytes: &[u8]) {
    let mut guard = session_key_zeroization_guard();
    guard.clear();
    guard.extend_from_slice(bytes);
}
#[doc(hidden)]
pub fn __debug_last_zeroized_session_key() -> Vec<u8> {
    session_key_zeroization_guard().clone()
}
#[doc(hidden)]
pub fn __debug_clear_last_zeroized_session_key() {
    session_key_zeroization_guard().clear();
}
/// A session key derived from a key exchange. Will usually be used for a symmetric encryption afterwards
pub struct SessionKey(ZeroizingConstVec);
impl SessionKey {
    /// Create a new [`SessionKey`] from raw key material.
    pub fn new(payload: Vec<u8>) -> Self {
        Self(ZeroizingConstVec::new(payload))
    }
    pub(crate) fn from_zeroizing_vec(mut payload: Zeroizing<Vec<u8>>) -> Self {
        Self::new(core::mem::take(&mut *payload))
    }
    /// Expose the raw bytes of the session key
    pub fn payload(&self) -> &[u8] {
        self.0.as_ref()
    }
}
impl From<Vec<u8>> for SessionKey {
    fn from(payload: Vec<u8>) -> Self {
        Self::new(payload)
    }
}
/// Shim for decoding hexadecimal strings
pub(crate) fn hex_decode<T: AsRef<[u8]> + ?Sized>(payload: &T) -> Result<Vec<u8>, ParseError> {
    let bytes = payload.as_ref();
    let trimmed = if bytes.len() >= 2 && bytes[0] == b'0' && matches!(bytes[1], b'x' | b'X') {
        &bytes[2..]
    } else {
        bytes
    };
    hex::decode(trimmed).map_err(|err| ParseError(err.to_string()))
}
pub mod error {
    //! Module containing errors
    use super::*;
    /// Error indicating algorithm could not be found
    #[derive(Debug, Display, Clone, Copy)]
    #[display("Algorithm not supported")]
    pub struct NoSuchAlgorithm;
    impl std::error::Error for NoSuchAlgorithm {}
    /// Error parsing a key
    #[derive(Debug, Display, Clone, PartialEq, Eq)]
    #[display("{_0}")]
    pub struct ParseError(pub(crate) String);
    impl std::error::Error for ParseError {}
    /// Error when dealing with cryptographic functions
    #[derive(Debug, Display, PartialEq, Eq)]
    pub enum Error {
        /// Returned when trying to create an algorithm which does not exist
        #[display("Algorithm '{_0}' is not supported")]
        NoSuchAlgorithm(String),
        /// Occurs during deserialization of a private or public key
        #[display("Key could not be parsed. {_0}")]
        Parse(ParseError),
        /// Returned when an error occurs during the signing process
        #[display("Signing failed. {_0}")]
        Signing(String),
        /// Returned when an error occurs during the signature verification process
        #[display("Signature verification failed")]
        BadSignature,
        /// Returned when an error occurs during key generation
        #[display("Key generation failed. {_0}")]
        KeyGen(String),
        /// A General purpose error message that doesn't fit in any category
        #[display("General error. {_0}")] // This is going to cause a headache
        Other(String),
    }
    impl From<NoSuchAlgorithm> for Error {
        fn from(source: NoSuchAlgorithm) -> Self {
            Self::NoSuchAlgorithm(source.to_string())
        }
    }
    impl From<ParseError> for Error {
        fn from(source: ParseError) -> Self {
            Self::Parse(source)
        }
    }
    impl std::error::Error for Error {}
}
include!("lib_tests.rs");
