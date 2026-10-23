// pub(crate) for inner modules it is not redundant, the contents of `signature` module get re-exported at root
#![allow(clippy::redundant_pub_crate)]
pub(crate) mod admission;
mod allocation;
mod borrowed_payload;
mod encoding;
#[cfg(feature = "bls")]
pub use allocation::PrepaidBlsSignatureError;
pub use allocation::{ChargedSignature, SignatureAllocationError};
#[cfg(feature = "bls")]
pub use bls::BlsSigningError;
pub use borrowed_payload::{BorrowedSignaturePayload, BorrowedSignaturePayloadError};
pub use encoding::{
    SignatureEncodingError, ed25519_validate_signature_encoding,
    mldsa65_validate_signature_encoding,
};
#[cfg(feature = "bls")]
pub(crate) mod bls;
pub(crate) mod ed25519;
#[cfg(feature = "gost")]
pub(crate) mod gost;
pub(crate) mod mldsa;
pub(crate) mod secp256k1;
#[cfg(feature = "sm")]
pub(crate) mod sm;
use crate::{
    Algorithm, Error, HashOf, PrivateKey, PublicKey, PublicKeyFull, PublicKeyMaterial,
    error::ParseError, hex_decode,
};
use core::marker::PhantomData;
use derive_more::{Deref, DerefMut};
use iroha_primitives::const_vec::ConstVec;
use iroha_schema::{IntoSchema, TypeId};
use norito::core::{self as ncore, DecodeFromSlice};
#[cfg(feature = "json")]
use norito::json::{self, FastJsonWrite, JsonDeserialize};
use std::{cell::RefCell, format, string::String, vec, vec::Vec};
use zeroize::Zeroize;
/// Represents a signature of the data (`Block` or `Transaction` for example).
#[derive(
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    getset::Getters,
    derive_more::Debug,
    Hash,
    IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_crypto::signature::Signature")]
#[repr(transparent)]
#[debug("{{ {} }}", hex::encode_upper(payload))]
pub struct Signature {
    payload: ConstVec<u8>,
}

impl Zeroize for Signature {
    fn zeroize(&mut self) {
        let mut bytes = core::mem::take(&mut self.payload).into_vec();
        bytes.zeroize();
        self.payload = ConstVec::from(bytes);
    }
}
const PUBLIC_KEY_FULL_CACHE_LIMIT: usize = 128;
const ED25519_PUBLIC_KEY_FULL_FAST_CACHE_SIZE: usize = 16_384;
struct PublicKeyFullCacheEntry {
    algorithm: u8,
    payload: Vec<u8>,
    full: PublicKeyFull,
}
#[derive(Clone, Copy)]
struct Ed25519PublicKeyFullFastEntry {
    payload: [u8; 32],
    full: ed25519::PublicKey,
}
struct PublicKeyFullFastCache {
    ed25519: Box<[Option<Ed25519PublicKeyFullFastEntry>]>,
    #[cfg(test)]
    ed25519_hits: usize,
    #[cfg(test)]
    ed25519_misses: usize,
    #[cfg(test)]
    ed25519_inserts: usize,
}
impl PublicKeyFullFastCache {
    fn new() -> Self {
        Self {
            ed25519: vec![None; ED25519_PUBLIC_KEY_FULL_FAST_CACHE_SIZE].into_boxed_slice(),
            #[cfg(test)]
            ed25519_hits: 0,
            #[cfg(test)]
            ed25519_misses: 0,
            #[cfg(test)]
            ed25519_inserts: 0,
        }
    }
    fn get_ed25519(&mut self, payload: &[u8]) -> Option<ed25519::PublicKey> {
        let payload: [u8; 32] = payload.try_into().ok()?;
        let slot = ed25519_public_key_full_fast_index(&payload);
        if let Some(entry) = self.ed25519[slot]
            && entry.payload == payload
        {
            #[cfg(test)]
            {
                self.ed25519_hits = self.ed25519_hits.saturating_add(1);
            }
            return Some(entry.full);
        }
        #[cfg(test)]
        {
            self.ed25519_misses = self.ed25519_misses.saturating_add(1);
        }
        None
    }
    fn insert_ed25519(&mut self, payload: [u8; 32], full: ed25519::PublicKey) {
        let slot = ed25519_public_key_full_fast_index(&payload);
        self.ed25519[slot] = Some(Ed25519PublicKeyFullFastEntry { payload, full });
        #[cfg(test)]
        {
            self.ed25519_inserts = self.ed25519_inserts.saturating_add(1);
        }
    }
    #[cfg(test)]
    fn reset(&mut self) {
        self.ed25519.fill(None);
        self.ed25519_hits = 0;
        self.ed25519_misses = 0;
        self.ed25519_inserts = 0;
    }
    #[cfg(test)]
    fn stats(&self) -> PublicKeyFullFastCacheStats {
        PublicKeyFullFastCacheStats {
            hits: self.ed25519_hits,
            misses: self.ed25519_misses,
            inserts: self.ed25519_inserts,
        }
    }
}
#[cfg(test)]
#[derive(Debug, Default, PartialEq, Eq)]
struct PublicKeyFullFastCacheStats {
    hits: usize,
    misses: usize,
    inserts: usize,
}
thread_local! {
    static PUBLIC_KEY_FULL_FAST_CACHE: RefCell<PublicKeyFullFastCache> =
        RefCell::new(PublicKeyFullFastCache::new());
    static PUBLIC_KEY_FULL_CACHE: RefCell<Vec<PublicKeyFullCacheEntry>> =
        const { RefCell::new(Vec::new()) };
}
#[inline]
fn ed25519_public_key_full_fast_index(payload: &[u8; 32]) -> usize {
    ed25519_public_key_full_fast_index_for_size(payload, ED25519_PUBLIC_KEY_FULL_FAST_CACHE_SIZE)
}
#[inline]
fn ed25519_public_key_full_fast_index_for_size(payload: &[u8; 32], cache_size: usize) -> usize {
    let Some(a) = le_u64_chunk(payload, 0) else {
        return 0;
    };
    let Some(b) = le_u64_chunk(payload, 8) else {
        return 0;
    };
    let Some(c) = le_u64_chunk(payload, 16) else {
        return 0;
    };
    let Some(d) = le_u64_chunk(payload, 24) else {
        return 0;
    };
    let Some(mask) = cache_size
        .checked_sub(1)
        .and_then(|mask| u64::try_from(mask).ok())
    else {
        return 0;
    };
    let mixed = a ^ b.rotate_left(17) ^ c.rotate_left(31) ^ d.rotate_left(47);
    usize::try_from(mixed & mask).unwrap_or(0)
}
#[inline]
fn le_u64_chunk(payload: &[u8; 32], start: usize) -> Option<u64> {
    let end = start.checked_add(8)?;
    let chunk = payload.get(start..end)?;
    let mut bytes = [0_u8; 8];
    bytes.copy_from_slice(chunk);
    Some(u64::from_le_bytes(bytes))
}
#[cfg(test)]
fn reset_public_key_full_fast_cache_for_tests() {
    PUBLIC_KEY_FULL_FAST_CACHE.with(|cache| cache.borrow_mut().reset());
}
#[cfg(test)]
fn public_key_full_fast_cache_stats_for_tests() -> PublicKeyFullFastCacheStats {
    PUBLIC_KEY_FULL_FAST_CACHE.with(|cache| cache.borrow().stats())
}
#[cfg(all(test, feature = "bls"))]
thread_local! {
    static BLS_FULL_KEY_CACHE_ACCESSES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(all(test, feature = "bls"))]
pub(crate) fn bls_full_key_cache_accesses_for_tests() -> usize {
    BLS_FULL_KEY_CACHE_ACCESSES.with(std::cell::Cell::get)
}

fn public_key_material_cached(public_key: &PublicKey) -> Result<PublicKeyMaterial<'_>, Error> {
    let (algorithm, payload) = public_key.try_to_bytes()?;
    if algorithm == Algorithm::MlDsa {
        return crate::parse_public_key_material(algorithm, payload).map_err(Error::from);
    }
    #[cfg(feature = "sm")]
    if algorithm == Algorithm::Sm2 {
        return crate::parse_public_key_material(algorithm, payload).map_err(Error::from);
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
        return crate::parse_public_key_material(algorithm, payload).map_err(Error::from);
    }
    #[cfg(all(test, feature = "bls"))]
    if matches!(algorithm, Algorithm::BlsNormal | Algorithm::BlsSmall) {
        BLS_FULL_KEY_CACHE_ACCESSES.with(|count| count.set(count.get() + 1));
    }
    if algorithm == Algorithm::Ed25519 {
        if let Some(full) =
            PUBLIC_KEY_FULL_FAST_CACHE.with(|cache| cache.borrow_mut().get_ed25519(payload))
        {
            return Ok(PublicKeyMaterial::Decoded(PublicKeyFull::Ed25519(full)));
        }
        let payload_bytes: [u8; 32] = payload
            .try_into()
            .map_err(|_| ParseError::Invalid("invalid Ed25519 public key length".to_owned()))?;
        let full = ed25519::Ed25519Sha512::parse_public_key(&payload_bytes)?;
        PUBLIC_KEY_FULL_FAST_CACHE.with(|cache| {
            cache.borrow_mut().insert_ed25519(payload_bytes, full);
        });
        return Ok(PublicKeyMaterial::Decoded(PublicKeyFull::Ed25519(full)));
    }
    let algorithm_tag = algorithm as u8;
    PUBLIC_KEY_FULL_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        if let Some(pos) = cache.iter().position(|entry| {
            entry.algorithm == algorithm_tag && entry.payload.as_slice() == payload
        }) {
            let entry = cache.remove(pos);
            let full = entry.full.clone();
            cache.push(entry);
            return Ok(PublicKeyMaterial::Decoded(full));
        }
        let material = crate::parse_public_key_material(algorithm, payload)?;
        let PublicKeyMaterial::Decoded(full) = material else {
            return Ok(material);
        };
        cache.push(PublicKeyFullCacheEntry {
            algorithm: algorithm_tag,
            payload: payload.to_vec(),
            full: full.clone(),
        });
        if cache.len() > PUBLIC_KEY_FULL_CACHE_LIMIT {
            let drain = cache.len() - PUBLIC_KEY_FULL_CACHE_LIMIT;
            cache.drain(0..drain);
        }
        Ok(PublicKeyMaterial::Decoded(full))
    })
}
impl Signature {
    /// Creates new signature by signing payload via [`crate::KeyPair::private_key`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::Signing`] when an algorithm-specific signing backend
    /// rejects the private-key material or message.
    pub fn try_new(private_key: &PrivateKey, payload: &[u8]) -> Result<Self, Error> {
        Self::try_new_with_context(private_key, &[], payload)
    }
    /// Creates a new signature with an algorithm-specific signing context.
    ///
    /// ML-DSA accepts the FIPS 204 context directly. Other algorithms have no
    /// compatible context field and therefore reject a nonempty context instead
    /// of silently dropping domain-separation input. An empty context is exactly
    /// equivalent to [`Self::try_new`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::Signing`] when a non-ML-DSA key is paired with a
    /// nonempty context, or when the algorithm-specific signing backend rejects
    /// the private-key material, context, or message.
    pub fn try_new_with_context(
        private_key: &PrivateKey,
        context: &[u8],
        payload: &[u8],
    ) -> Result<Self, Error> {
        use crate::secrecy::ExposeSecret;
        let signature = match private_key.0.expose_secret() {
            crate::PrivateKeyInner::Ed25519(sk) => {
                reject_unsupported_signing_context(context, Algorithm::Ed25519)?;
                ed25519::Ed25519Sha512::sign(payload, sk)
            }
            crate::PrivateKeyInner::Secp256k1(sk) => {
                reject_unsupported_signing_context(context, Algorithm::Secp256k1)?;
                secp256k1::EcdsaSecp256k1Sha256::try_sign(payload, sk)?
            }
            #[cfg(feature = "pqc")]
            crate::PrivateKeyInner::MlDsa(sk) if context.is_empty() => sk.try_sign(payload)?,
            #[cfg(feature = "pqc")]
            crate::PrivateKeyInner::MlDsa(sk) => sk.try_sign_with_context(context, payload)?,
            #[cfg(feature = "gost")]
            crate::PrivateKeyInner::Gost { algorithm, secret } => {
                reject_unsupported_signing_context(context, *algorithm)?;
                gost::sign(*algorithm, payload, secret)?
            }
            #[cfg(feature = "bls")]
            crate::PrivateKeyInner::BlsSmall(sk) => {
                reject_unsupported_signing_context(context, Algorithm::BlsSmall)?;
                bls::BlsSmall::try_sign(payload, sk)?
            }
            #[cfg(feature = "bls")]
            crate::PrivateKeyInner::BlsNormal(sk) => {
                reject_unsupported_signing_context(context, Algorithm::BlsNormal)?;
                bls::BlsNormal::try_sign(payload, sk)?
            }
            #[cfg(feature = "sm")]
            crate::PrivateKeyInner::Sm2(sk) => {
                reject_unsupported_signing_context(context, Algorithm::Sm2)?;
                sk.try_sign(payload)?.as_bytes().to_vec()
            }
        };
        Ok(Self {
            payload: ConstVec::new(signature),
        })
    }
    #[cfg(feature = "pqc")]
    pub(crate) fn try_new_mldsa_with_context_and_hedged_rng(
        private_key: &PrivateKey,
        context: &[u8],
        payload: &[u8],
        rng: &mut soranet_pq::HedgedChaCha20Rng,
    ) -> Result<Self, Error> {
        use crate::secrecy::ExposeSecret;
        let crate::PrivateKeyInner::MlDsa(secret_key) = private_key.0.expose_secret() else {
            return Err(Error::Signing(
                "context-bound hedged signing requires an ML-DSA private key".to_owned(),
            ));
        };
        let signature = secret_key.try_sign_with_context_and_hedged_rng(context, payload, rng)?;
        Ok(Self {
            payload: ConstVec::new(signature),
        })
    }
    /// Creates new signature by signing payload via [`crate::KeyPair::private_key`].
    pub fn new(private_key: &PrivateKey, payload: &[u8]) -> Self {
        Self::try_new(private_key, payload)
            .expect("signing should succeed for a valid private key and payload")
    }
    /// Get the raw payload of the signature.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
    /// Creates new signature from its raw payload and public key.
    ///
    /// **This method does not sign the payload.** Use [`Signature::new`] for this purpose.
    ///
    /// This method exists to allow reproducing the signature in a more efficient way than through
    /// deserialization.
    pub fn from_bytes(payload: &[u8]) -> Self {
        Self {
            payload: ConstVec::new(payload),
        }
    }
    /// Fallibly create a signature from raw bytes received from an external boundary.
    ///
    /// This preserves [`Signature::from_bytes`] for tests and callers that intentionally reproduce
    /// opaque bytes, while giving protocol adapters a checked constructor for admitting externally
    /// supplied signatures.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] if `payload` is empty or contains only zero bytes.
    pub fn try_from_bytes(payload: &[u8]) -> Result<Self, ParseError> {
        validate_signature_payload_for_admission(payload)?;
        Ok(Self::from_bytes(payload))
    }

    /// Check the canonical raw payload without copying or granting signature authority.
    ///
    /// # Errors
    /// Rejects the same empty or all-zero payload as the canonical owned constructor.
    pub fn validate_payload(payload: &[u8]) -> Result<(), SignaturePayloadError> {
        validate_signature_payload(payload)
    }

    /// Fallibly retain exact signature bytes at an admission boundary.
    ///
    /// # Errors
    ///
    /// Returns a fixed parse error for empty/all-zero input and a decode
    /// allocation error if the exact payload destination cannot be created.
    #[doc(hidden)]
    #[allow(unsafe_code)]
    pub fn try_from_bytes_for_admission(payload: &[u8]) -> Result<Self, norito::core::Error> {
        validate_signature_payload_for_admission(payload)
            .map_err(|_| norito::core::Error::Message("invalid signature".to_owned()))?;
        if payload.is_empty() {
            return Err(norito::core::Error::Message("invalid signature".to_owned()));
        }
        norito::core::reserve_decode_allocation(payload.len())?;
        let layout = std::alloc::Layout::array::<u8>(payload.len())
            .map_err(|_| norito::core::Error::LengthMismatch)?;
        // SAFETY: the non-zero layout describes exactly `payload.len()` bytes;
        // a null allocation is handled before ownership is constructed.
        let allocation = unsafe { std::alloc::alloc(layout) };
        if allocation.is_null() {
            return Err(norito::core::Error::AllocationFailed {
                bytes: u64::try_from(payload.len()).unwrap_or(u64::MAX),
            });
        }
        // SAFETY: source and destination are valid, non-overlapping buffers of
        // exactly `payload.len()` bytes.
        unsafe { std::ptr::copy_nonoverlapping(payload.as_ptr(), allocation, payload.len()) };
        let slice = std::ptr::slice_from_raw_parts_mut(allocation, payload.len());
        // SAFETY: `slice` is the exact allocation described above and is fully
        // initialized by the copy.
        Ok(Self {
            payload: ConstVec::new(unsafe { Box::from_raw(slice) }),
        })
    }
    /// A shorthand for [`Self::from_bytes`] accepting payload as hex.
    ///
    /// # Errors
    /// If passed string is not a valid hex.
    pub fn from_hex(payload: impl AsRef<str>) -> Result<Self, ParseError> {
        let payload: Vec<u8> = hex_decode(payload.as_ref())?;
        Ok(Self::from_bytes(&payload))
    }
    /// Fallibly create a signature from hex received from an external boundary.
    ///
    /// This preserves [`Signature::from_hex`] for tests and callers that intentionally reproduce
    /// opaque bytes, while rejecting empty or all-zero payloads for admission paths.
    ///
    /// # Errors
    /// Returns [`ParseError`] when the string is not valid hex, or when the
    /// decoded payload is empty or all zero.
    pub fn try_from_hex(payload: impl AsRef<str>) -> Result<Self, ParseError> {
        let payload: Vec<u8> = hex_decode(payload.as_ref())?;
        Self::try_from_bytes(&payload)
    }
    /// Verify `payload` using signed data and [`crate::KeyPair::public_key`].
    ///
    /// # Errors
    /// Fails if the message doesn't pass verification
    pub fn verify(&self, public_key: &PublicKey, payload: &[u8]) -> Result<(), Error> {
        let algorithm = public_key.try_algorithm()?;
        if algorithm != Algorithm::MlDsa {
            algorithm
                .require_implementation(crate::CryptoOperation::VerifySignature)
                .map_err(Error::UnsupportedImplementation)?;
        }
        #[cfg(feature = "bls")]
        {
            let (algorithm, key_bytes) = public_key.try_to_bytes()?;
            if matches!(algorithm, Algorithm::BlsNormal | Algorithm::BlsSmall) {
                return bls::verify_signature_bytes(algorithm, key_bytes, &self.payload, payload);
            }
        }
        let material = public_key_material_cached(public_key)?;
        let public_key_full = match material {
            PublicKeyMaterial::MlDsa(bytes) => {
                return mldsa::verify(bytes, &self.payload, payload)
                    .map_err(mldsa::Rejection::into_error);
            }
            #[cfg(feature = "sm")]
            PublicKeyMaterial::Sm2(key) => return key.verify(payload, &self.payload),
            #[cfg(feature = "gost")]
            PublicKeyMaterial::Gost { algorithm, bytes } => {
                return gost::verify_bytes(algorithm, payload, &self.payload, bytes);
            }
            PublicKeyMaterial::Decoded(key) => key,
        };
        if signature_payload_is_all_zero(&self.payload) {
            return Err(Error::BadSignature);
        }
        match &public_key_full {
            PublicKeyFull::Ed25519(pk) => {
                ed25519::Ed25519Sha512::verify(payload, &self.payload, pk)
            }
            PublicKeyFull::Secp256k1(pk) => {
                secp256k1::EcdsaSecp256k1Sha256::verify(payload, &self.payload, pk)
            }
            #[cfg(feature = "bls")]
            PublicKeyFull::BlsSmall { key, .. } => {
                if self.payload.len() != bls::BlsSmall::signature_len() {
                    return Err(Error::BadSignature);
                }
                bls::BlsSmall::verify(payload, &self.payload, key)
            }
            #[cfg(feature = "bls")]
            PublicKeyFull::BlsNormal { key, .. } => {
                if self.payload.len() != bls::BlsNormal::signature_len() {
                    return Err(Error::BadSignature);
                }
                bls::BlsNormal::verify(payload, &self.payload, key)
            }
        }?;
        Ok(())
    }
}
fn reject_unsupported_signing_context(context: &[u8], algorithm: Algorithm) -> Result<(), Error> {
    if context.is_empty() {
        Ok(())
    } else {
        Err(Error::Signing(format!(
            "{algorithm} does not support a signing context"
        )))
    }
}
fn signature_payload_is_all_zero(payload: &[u8]) -> bool {
    !payload.is_empty() && payload.iter().all(|&byte| byte == 0)
}
/// Fixed canonical signature-payload rejection; it establishes no signature authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignaturePayloadError {
    /// The encoded signature has no bytes.
    Empty,
    /// Every encoded signature byte is zero.
    AllZero,
}

impl core::fmt::Display for SignaturePayloadError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::Empty => "signature payload must not be empty",
            Self::AllZero => "signature payload must not be all zero",
        })
    }
}
impl std::error::Error for SignaturePayloadError {}

pub(crate) fn validate_signature_payload(payload: &[u8]) -> Result<(), SignaturePayloadError> {
    validate_signature_payload_observation(payload.len(), payload.iter().any(|&byte| byte != 0))
}
fn validate_signature_payload_observation(
    length: usize,
    has_nonzero: bool,
) -> Result<(), SignaturePayloadError> {
    if length == 0 {
        return Err(SignaturePayloadError::Empty);
    }
    if !has_nonzero {
        return Err(SignaturePayloadError::AllZero);
    }
    Ok(())
}
fn validate_signature_payload_for_admission(payload: &[u8]) -> Result<(), ParseError> {
    validate_signature_payload(payload).map_err(|error| ParseError::Invalid(error.to_string()))
}

#[allow(unsafe_code)]
fn allocate_signature_payload_exact(length: usize) -> Result<Box<[u8]>, ncore::Error> {
    if length == 0 {
        return Ok(Box::default());
    }
    let layout =
        std::alloc::Layout::array::<u8>(length).map_err(|_| ncore::Error::LengthMismatch)?;
    // SAFETY: the non-zero layout describes exactly `length` bytes. A null
    // result is handled before ownership is constructed.
    let allocation = unsafe { std::alloc::alloc_zeroed(layout) };
    if allocation.is_null() {
        return Err(ncore::Error::AllocationFailed {
            bytes: u64::try_from(length).unwrap_or(u64::MAX),
        });
    }
    let slice = std::ptr::slice_from_raw_parts_mut(allocation, length);
    // SAFETY: `alloc_zeroed` initialized the exact allocation above.
    Ok(unsafe { Box::from_raw(slice) })
}

/// Decode the canonical `ConstVec<u8>` layout: a sequence count
/// followed by one exactly framed byte per element.
pub(crate) fn signature_payload_geometry(bytes: &[u8]) -> Result<(usize, usize), ncore::Error> {
    let (count, raw_start) = ncore::read_seq_len_slice(bytes)?;
    if count > bytes.len().saturating_sub(raw_start) {
        return Err(ncore::Error::LengthMismatch);
    }
    Ok((count, raw_start))
}

/// Fill the original initialized destination using the sole signature element walk.
/// Geometry accounting precedes this kernel exactly once in both callers.
pub(crate) fn decode_signature_payload_elements(
    bytes: &[u8],
    offset: usize,
    destination: &mut [u8],
) -> Result<(), ncore::Error> {
    visit_signature_payload_elements(bytes, offset, destination.len(), |index, byte| {
        destination[index] = byte;
    })
}

/// The sole canonical signature byte walk, shared by owning and borrowed custody.
fn visit_signature_payload_elements(
    bytes: &[u8],
    mut offset: usize,
    count: usize,
    mut visit: impl FnMut(usize, u8),
) -> Result<(), ncore::Error> {
    for index in 0..count {
        let (elem_len, header_len) = ncore::inspect_len_from_slice(
            bytes.get(offset..).ok_or(ncore::Error::LengthMismatch)?,
        )?;
        if elem_len != 1 {
            return Err(ncore::Error::LengthMismatch);
        }
        offset = offset
            .checked_add(header_len)
            .ok_or(ncore::Error::LengthMismatch)?;
        let byte = *bytes.get(offset).ok_or(ncore::Error::LengthMismatch)?;
        visit(index, byte);
        offset = offset
            .checked_add(elem_len)
            .ok_or(ncore::Error::LengthMismatch)?;
    }
    if offset != bytes.len() {
        return Err(ncore::Error::LengthMismatch);
    }
    Ok(())
}

fn decode_signature_payload_unpacked(bytes: &[u8]) -> Result<ConstVec<u8>, ncore::Error> {
    let (count, raw_start) = signature_payload_geometry(bytes)?;
    // The sequence reader already charged one retained byte per u8 element.
    let mut payload = allocate_signature_payload_exact(count)?;
    decode_signature_payload_elements(bytes, raw_start, &mut payload)?;
    Ok(ConstVec::new(payload))
}

fn decode_signature_payload_from_slice(
    bytes: &[u8],
) -> Result<(ConstVec<u8>, usize), ncore::Error> {
    decode_signature_payload_unpacked(bytes).map(|payload| (payload, bytes.len()))
}
fn validate_signature_payload_for_decode(payload: &[u8]) -> Result<(), ncore::Error> {
    validate_signature_payload_for_admission(payload)
        .map_err(|err| ncore::Error::Message(err.to_string()))
}
#[cfg(feature = "json")]
impl FastJsonWrite for Signature {
    fn write_json(&self, out: &mut String) {
        let encoded = hex::encode_upper(self.payload());
        json::write_json_string(&encoded, out);
    }
    fn write_json_to(
        &self,
        out: &mut dyn json::JsonWriteSink,
    ) -> Result<(), json::BoundedJsonError> {
        json::write_upper_hex_json_string_to(self.payload(), out)
    }
}
#[cfg(feature = "json")]
impl JsonDeserialize for Signature {
    fn json_deserialize(parser: &mut json::Parser<'_>) -> Result<Self, json::Error> {
        let encoded = parser.parse_string()?;
        Signature::try_from_hex(&encoded).map_err(|err| json::Error::Message(err.to_string()))
    }
}
impl<T> From<SignatureOf<T>> for Signature {
    fn from(SignatureOf(signature, ..): SignatureOf<T>) -> Self {
        signature
    }
}
/// Represents signature of the data (`Block` or `Transaction` for example).
// Lint triggers when expanding #[codec(skip)]
#[allow(clippy::default_trait_access, clippy::unsafe_derive_deserialize)]
#[derive(Deref, DerefMut, TypeId)]
// Transmute guard
#[repr(transparent)]
pub struct SignatureOf<T>(
    #[deref]
    #[deref_mut]
    Signature,
    PhantomData<T>,
);
impl<T> core::fmt::Debug for SignatureOf<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple(core::any::type_name::<Self>())
            .field(&self.0)
            .finish()
    }
}
impl<T> Clone for SignatureOf<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone(), PhantomData)
    }
}
impl<T> Zeroize for SignatureOf<T> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
#[allow(clippy::unconditional_recursion)] // False-positive
impl<T> PartialEq for SignatureOf<T> {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq(&other.0)
    }
}
impl<T> Eq for SignatureOf<T> {}
impl<T> PartialOrd for SignatureOf<T> {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl<T> Ord for SignatureOf<T> {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}
impl<T> core::hash::Hash for SignatureOf<T> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}
impl<T: IntoSchema> IntoSchema for SignatureOf<T> {
    fn type_name() -> String {
        format!("SignatureOf<{}>", T::type_name())
    }
    fn update_schema_map(map: &mut iroha_schema::MetaMap) {
        if !map.contains_key::<Self>() {
            map.insert::<Self>(iroha_schema::Metadata::Tuple(
                iroha_schema::UnnamedFieldsMeta {
                    types: vec![core::any::TypeId::of::<Signature>()],
                },
            ));
            Signature::update_schema_map(map);
        }
    }
}
/// Archived representation of [`SignatureOf`].
pub type ArchivedSignatureOf<T> = norito::core::Archived<SignatureOf<T>>;

impl ncore::SerializePayload for Signature {
    fn serialize(&self, writer: &mut ncore::Encoder<'_>) -> Result<(), ncore::Error> {
        self.payload.serialize(writer)
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        self.payload.encoded_len_hint()
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        self.payload.encoded_len_exact()
    }
}

impl<'de> ncore::DeserializePayload<'de> for Signature {
    fn deserialize(archived: &'de ncore::Archived<Self>) -> Self {
        Self::try_deserialize(archived).expect("Signature decode")
    }
    fn try_deserialize(archived: &'de ncore::Archived<Self>) -> Result<Self, ncore::Error> {
        let bytes = ncore::payload_slice_from_ptr(core::ptr::from_ref(archived).cast::<u8>())?;
        let payload = decode_signature_payload_unpacked(bytes)?;
        ncore::note_payload_access(bytes, bytes.len());
        validate_signature_payload_for_decode(&payload)?;
        Ok(Signature { payload })
    }
}
// Use default Norito derives for SignatureOf<T> provided by the crate macros.
impl<'a> norito::core::DecodeFromSlice<'a> for Signature {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        let (payload, used) = decode_signature_payload_from_slice(bytes)?;
        validate_signature_payload_for_decode(&payload)?;
        Ok((Signature { payload }, used))
    }
}
impl<T: norito::NoritoSchema> norito::NoritoSchema for SignatureOf<T> {
    fn nominal_name() -> String {
        norito::schema::identity::generic_name(
            "iroha_crypto::signature::SignatureOf",
            &[T::nominal_name()],
        )
    }
}

impl<T> norito::core::SerializePayload for SignatureOf<T> {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), norito::core::Error> {
        // Delegate to inner Signature so SignatureOf has identical on-wire bytes.
        norito::core::SerializePayload::serialize(&self.0, writer)
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        norito::core::SerializePayload::encoded_len_hint(&self.0)
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        norito::core::SerializePayload::encoded_len_exact(&self.0)
    }
}

impl<'de, T> norito::core::DeserializePayload<'de> for SignatureOf<T> {
    fn deserialize(archived: &'de norito::core::Archived<Self>) -> Self {
        Self::try_deserialize(archived).expect("SignatureOf decode")
    }
    fn try_deserialize(
        archived: &'de norito::core::Archived<Self>,
    ) -> Result<Self, norito::core::Error> {
        let signature = Signature::try_deserialize(archived.cast::<Signature>())?;
        Ok(SignatureOf(signature, PhantomData))
    }
}
#[cfg(feature = "json")]
impl<T> FastJsonWrite for SignatureOf<T> {
    fn write_json(&self, out: &mut String) {
        self.0.write_json(out);
    }
    fn write_json_to(
        &self,
        out: &mut dyn json::JsonWriteSink,
    ) -> Result<(), json::BoundedJsonError> {
        self.0.write_json_to(out)
    }
}
#[cfg(feature = "json")]
impl<T> JsonDeserialize for SignatureOf<T> {
    fn json_deserialize(parser: &mut json::Parser<'_>) -> Result<Self, json::Error> {
        Signature::json_deserialize(parser).map(|sig| SignatureOf(sig, PhantomData))
    }
}
// Norito already provides blanket `Encode`/`Decode` implementations via the
// `NoritoSerialize`/`NoritoDeserialize` traits. However, packed sequence layouts
// used by `ConstVec<u8>` require the slice decoder to cooperate with the Norito
// payload context, so we keep this focused bridge that simply delegates to the
// inner `Signature`.
impl<'a, T> DecodeFromSlice<'a> for SignatureOf<T> {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        let (inner, used) = <Signature as DecodeFromSlice>::decode_from_slice(bytes)?;
        Ok((SignatureOf(inner, PhantomData), used))
    }
}
impl<T> SignatureOf<T> {
    /// Wipe signature bytes before discarding a confidential typed copy.
    ///
    /// The signature intentionally becomes invalid and must not be used after
    /// this call. This is for restricted plaintext containers in which an
    /// otherwise-public signature is itself confidential metadata.
    pub fn zeroize_for_confidential_discard(&mut self) {
        <Self as Zeroize>::zeroize(self);
    }

    /// Fallibly create [`SignatureOf`] from the given hash with [`crate::KeyPair::private_key`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::Signing`] when an algorithm-specific signing backend
    /// rejects the private-key material or hash payload.
    #[inline]
    pub fn try_from_hash(private_key: &PrivateKey, hash: HashOf<T>) -> Result<Self, Error> {
        Signature::try_new(private_key, hash.as_ref()).map(|signature| Self(signature, PhantomData))
    }
    /// Create [`SignatureOf`] from the given hash with [`crate::KeyPair::private_key`].
    #[inline]
    pub fn from_hash(private_key: &PrivateKey, hash: HashOf<T>) -> Self {
        Self::try_from_hash(private_key, hash)
            .expect("signing should succeed for a valid private key and hash payload")
    }
    /// Construct [`SignatureOf`] from an already-produced [`Signature`].
    #[inline]
    pub fn from_signature(signature: Signature) -> Self {
        Self(signature, PhantomData)
    }
    /// Verify signature for this hash
    ///
    /// # Errors
    ///
    /// Fails if the given hash didn't pass verification
    pub fn verify_hash(&self, public_key: &PublicKey, hash: HashOf<T>) -> Result<(), Error> {
        self.0.verify(public_key, hash.as_ref())
    }
}
impl<T: norito::codec::Encode> SignatureOf<T> {
    /// Fallibly create [`SignatureOf`] by signing the given value with
    /// [`crate::KeyPair::private_key`].
    /// The value provided will be hashed before being signed. If you already have the
    /// hash of the value you can sign it with [`SignatureOf::try_from_hash`] instead.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Signing`] when an algorithm-specific signing backend
    /// rejects the private-key material or hash payload.
    #[inline]
    pub fn try_new(private_key: &PrivateKey, value: &T) -> Result<Self, Error> {
        let h = HashOf::new(value);
        Self::try_from_hash(private_key, h)
    }
    /// Create [`SignatureOf`] by signing the given value with [`crate::KeyPair::private_key`].
    /// The value provided will be hashed before being signed. If you already have the
    /// hash of the value you can sign it with [`SignatureOf::from_hash`] instead.
    #[inline]
    pub fn new(private_key: &PrivateKey, value: &T) -> Self {
        Self::try_new(private_key, value)
            .expect("signing should succeed for a valid private key and value")
    }
    /// Verifies signature for this item
    ///
    /// # Errors
    /// Fails if verification fails
    pub fn verify(&self, public_key: &PublicKey, value: &T) -> Result<(), Error> {
        self.verify_hash(public_key, HashOf::new(value))
    }
}
// Provide slice-based decoding for Signature as well (used by hybrid decoders)
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Algorithm, KeyGenOption, KeyPair, PublicKeyCompact};
    #[cfg(feature = "rand")]
    fn checked_random_keypair(algorithm: Algorithm) -> KeyPair {
        KeyPair::try_random_with_algorithm(algorithm).expect("generate checked random keypair")
    }
    fn checked_signature(key_pair: &KeyPair, message: &[u8]) -> Signature {
        Signature::try_new(key_pair.private_key(), message).expect("sign checked signature fixture")
    }
    const ED25519_SMALL_ORDER_R: [u8; 32] = [
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ];
    const ED25519_NONCANONICAL_R: [u8; 32] = [
        0x1a, 0xd5, 0x25, 0x8f, 0x60, 0x2d, 0x56, 0xc9, 0xb2, 0xa7, 0x25, 0x95, 0x60, 0xc7, 0x2c,
        0x69, 0x5c, 0xdc, 0xd6, 0xfd, 0x31, 0xe2, 0xa4, 0xc0, 0xfe, 0x53, 0x6e, 0xcd, 0xd3, 0x36,
        0x69, 0x92,
    ];
    #[test]
    #[cfg(feature = "rand")]
    fn create_signature_ed25519() {
        let key_pair = checked_random_keypair(Algorithm::Ed25519);
        let wrong_key = checked_random_keypair(Algorithm::Ed25519);
        let message = b"Test message to sign.";
        let signature = checked_signature(&key_pair, message);
        signature.verify(key_pair.public_key(), message).unwrap();
        signature
            .verify(wrong_key.public_key(), message)
            .expect_err("Ed25519 signature rejects wrong key");
    }
    #[test]
    #[cfg(feature = "rand")]
    fn create_signature_secp256k1() {
        let key_pair = checked_random_keypair(Algorithm::Secp256k1);
        let wrong_key = checked_random_keypair(Algorithm::Secp256k1);
        let message = b"Test message to sign.";
        let signature = checked_signature(&key_pair, message);
        signature.verify(key_pair.public_key(), message).unwrap();
        signature
            .verify(wrong_key.public_key(), message)
            .expect_err("secp256k1 signature rejects wrong key");
    }
    #[test]
    fn create_signature_secp256k1_checked_path() {
        let key_pair = KeyPair::try_from_seed(vec![0x51; 32], Algorithm::Secp256k1)
            .expect("seeded secp256k1 keypair");
        let message = b"Test message to sign with checked secp256k1.";
        let signature = Signature::try_new(key_pair.private_key(), message)
            .expect("checked secp256k1 signature");
        signature.verify(key_pair.public_key(), message).unwrap();
    }
    #[test]
    fn empty_signing_context_preserves_ed25519_signature_bytes() {
        let key_pair = KeyPair::try_from_seed(vec![0x52; 32], Algorithm::Ed25519)
            .expect("seeded Ed25519 keypair");
        let message = b"empty-context compatibility";
        let legacy = Signature::try_new(key_pair.private_key(), message)
            .expect("legacy empty-context signature");
        let explicit = Signature::try_new_with_context(key_pair.private_key(), &[], message)
            .expect("explicit empty-context signature");
        assert_eq!(legacy, explicit);
    }
    #[test]
    fn non_mldsa_signing_rejects_nonempty_context() {
        let key_pair = KeyPair::try_from_seed(vec![0x53; 32], Algorithm::Ed25519)
            .expect("seeded Ed25519 keypair");
        let error = Signature::try_new_with_context(
            key_pair.private_key(),
            b"unsupported-context",
            b"message",
        )
        .expect_err("Ed25519 must not silently discard an ML-DSA context");
        assert!(matches!(error, Error::Signing(_)));
        assert!(
            error
                .to_string()
                .contains("does not support a signing context")
        );
    }
    #[cfg(feature = "pqc")]
    #[test]
    fn mldsa_signing_binds_nonempty_context_without_copying_private_payload() {
        let key_pair = KeyPair::try_from_seed(vec![0x54; 32], Algorithm::MlDsa)
            .expect("seeded ML-DSA-65 keypair");
        let context = b"iroha.crypto.signature.context-test.v1";
        let message = b"context-bound ML-DSA message";
        let signature = Signature::try_new_with_context(key_pair.private_key(), context, message)
            .expect("context-bound ML-DSA signature");
        let (algorithm, public_key) = key_pair
            .public_key()
            .try_to_bytes()
            .expect("ML-DSA public key bytes");
        assert_eq!(algorithm, Algorithm::MlDsa);
        soranet_pq::verify_mldsa(
            soranet_pq::MlDsaSuite::MlDsa65,
            public_key,
            context,
            message,
            signature.payload(),
        )
        .expect("matching ML-DSA context verifies");
        soranet_pq::verify_mldsa(
            soranet_pq::MlDsaSuite::MlDsa65,
            public_key,
            b"wrong-context",
            message,
            signature.payload(),
        )
        .expect_err("different ML-DSA context must fail verification");
    }
    #[test]
    #[cfg(feature = "sm")]
    fn create_signature_sm2_checked_path() {
        let key_pair =
            KeyPair::try_from_seed(vec![0x42; 32], Algorithm::Sm2).expect("seeded SM2 keypair");
        let message = b"Test message to sign with checked SM2.";
        let signature =
            Signature::try_new(key_pair.private_key(), message).expect("checked SM2 signature");
        signature.verify(key_pair.public_key(), message).unwrap();
    }
    #[test]
    #[cfg(all(feature = "rand", feature = "bls"))]
    fn create_signature_bls_normal() {
        let key_pair = checked_random_keypair(Algorithm::BlsNormal);
        let wrong_key = checked_random_keypair(Algorithm::BlsNormal);
        let message = b"Test message to sign.";
        let signature = checked_signature(&key_pair, message);
        signature.verify(key_pair.public_key(), message).unwrap();
        signature
            .verify(wrong_key.public_key(), message)
            .expect_err("BLS normal signature rejects wrong key");
    }
    #[test]
    #[cfg(all(feature = "rand", feature = "bls"))]
    fn create_signature_bls_small() {
        let key_pair = checked_random_keypair(Algorithm::BlsSmall);
        let wrong_key = checked_random_keypair(Algorithm::BlsSmall);
        let message = b"Test message to sign.";
        let signature = checked_signature(&key_pair, message);
        signature.verify(key_pair.public_key(), message).unwrap();
        signature
            .verify(wrong_key.public_key(), message)
            .expect_err("BLS small signature rejects wrong key");
    }
    #[test]
    #[cfg(all(feature = "rand", feature = "bls"))]
    fn signature_verify_rejects_noncanonical_bls_lengths() {
        for algorithm in [Algorithm::BlsNormal, Algorithm::BlsSmall] {
            let key_pair = checked_random_keypair(algorithm);
            let message = b"BLS signature length boundary";
            let signature = checked_signature(&key_pair, message);
            let expected_len = match algorithm {
                Algorithm::BlsNormal => bls::BlsNormal::signature_len(),
                Algorithm::BlsSmall => bls::BlsSmall::signature_len(),
                _ => unreachable!("loop contains only BLS algorithms"),
            };
            assert_eq!(signature.payload().len(), expected_len);
            let shortened = Signature::from_bytes(&signature.payload()[1..]);
            shortened
                .verify(key_pair.public_key(), message)
                .expect_err("short BLS signature must fail at the public boundary");
            let mut extended = signature.payload().to_vec();
            extended.push(0x01);
            Signature::from_bytes(&extended)
                .verify(key_pair.public_key(), message)
                .expect_err("long BLS signature must fail at the public boundary");
        }
    }
    #[test]
    #[cfg(feature = "rand")]
    fn signature_verify_cache_separates_keys() {
        let key_one = checked_random_keypair(Algorithm::Ed25519);
        let key_two = checked_random_keypair(Algorithm::Ed25519);
        let message = b"Signature verify cache test";
        let signature = checked_signature(&key_one, message);
        signature.verify(key_one.public_key(), message).unwrap();
        assert!(
            signature.verify(key_two.public_key(), message).is_err(),
            "cache must not mix distinct public keys"
        );
        signature.verify(key_one.public_key(), message).unwrap();
    }
    #[test]
    fn ed25519_public_key_full_fast_cache_hits_after_first_lookup() {
        let (raw_public, _) = ed25519::Ed25519Sha512::keypair(KeyGenOption::UseSeed(vec![7u8; 32]));
        let public_key = PublicKey::new(PublicKeyFull::Ed25519(raw_public));
        reset_public_key_full_fast_cache_for_tests();
        let first = public_key_material_cached(&public_key).expect("public key parses");
        assert!(matches!(
            first,
            PublicKeyMaterial::Decoded(PublicKeyFull::Ed25519(_))
        ));
        assert_eq!(
            public_key_full_fast_cache_stats_for_tests(),
            PublicKeyFullFastCacheStats {
                hits: 0,
                misses: 1,
                inserts: 1,
            }
        );
        let second = public_key_material_cached(&public_key).expect("public key parses");
        assert!(matches!(
            second,
            PublicKeyMaterial::Decoded(PublicKeyFull::Ed25519(_))
        ));
        assert_eq!(
            public_key_full_fast_cache_stats_for_tests(),
            PublicKeyFullFastCacheStats {
                hits: 1,
                misses: 1,
                inserts: 1,
            }
        );
    }
    #[test]
    fn ed25519_public_key_full_fast_index_is_total() {
        let payload = [0xA5; 32];
        assert_eq!(ed25519_public_key_full_fast_index_for_size(&payload, 0), 0);
        assert_eq!(ed25519_public_key_full_fast_index_for_size(&payload, 1), 0);
        let index = ed25519_public_key_full_fast_index(&payload);
        assert!(index < ED25519_PUBLIC_KEY_FULL_FAST_CACHE_SIZE);
        assert_eq!(index, ed25519_public_key_full_fast_index(&payload));
    }
    #[test]
    fn signature_verify_rejects_malformed_cached_ed25519_public_key_without_panic() {
        let malformed = PublicKey(PublicKeyCompact::new(Algorithm::Ed25519, &[]));
        let signature = Signature::from_bytes(&[0u8; 64]);
        let err = signature
            .verify(&malformed, b"message")
            .expect_err("malformed public key must fail verification");
        assert!(matches!(err, Error::Parse(_)));
    }
    #[cfg(feature = "sm")]
    #[test]
    fn sm2_malformed_compact_key_precedes_empty_or_zero_signature_rejection() {
        for (payload, expected) in [
            (&[][..], "SM2 payload missing distid length prefix"),
            (&[0, 2, b'x'][..], "SM2 payload truncated distid"),
            (&[0, 1, 0xff][..], "SM2 distid must be valid UTF-8"),
            (&[0, 0][..], "SM2 public key payload must be 65 bytes"),
        ] {
            let malformed = PublicKey(PublicKeyCompact::new(Algorithm::Sm2, payload));
            for bytes in [&[][..], &[0; 64][..]] {
                let signature = Signature::from_bytes(bytes);
                for result in [
                    signature.verify(&malformed, b"message"),
                    crate::verify_signature_for_admission(&signature, &malformed, b"message"),
                ] {
                    let Err(Error::Parse(error)) = result else {
                        panic!("malformed SM2 key must retain parse-error precedence");
                    };
                    assert_eq!(error.to_string(), expected);
                }
            }
        }
    }
    #[test]
    fn signature_verify_rejects_all_zero_payload_before_backend() {
        let key_pair = KeyPair::try_from_seed(vec![0x44; 32], Algorithm::Ed25519)
            .expect("seeded Ed25519 keypair");
        let signature = Signature::from_bytes(&[0u8; 64]);
        let err = signature
            .verify(key_pair.public_key(), b"message")
            .expect_err("all-zero signature payload must fail closed");
        assert!(matches!(err, Error::BadSignature));
    }
    #[test]
    fn signature_verify_rejects_malformed_ed25519_r_before_backend() {
        let key_pair = KeyPair::try_from_seed(vec![0x46; 32], Algorithm::Ed25519)
            .expect("seeded Ed25519 keypair");
        let message = b"iroha:generic-signature-ed25519-r-admission";
        let valid_signature = checked_signature(&key_pair, message);
        valid_signature
            .verify(key_pair.public_key(), message)
            .expect("valid signature verifies before mutation");
        for (label, replacement_r) in [
            ("small-order", ED25519_SMALL_ORDER_R),
            ("noncanonical", ED25519_NONCANONICAL_R),
        ] {
            let mut payload = valid_signature.payload().to_vec();
            payload[..replacement_r.len()].copy_from_slice(&replacement_r);
            let signature = Signature::from_bytes(&payload);
            let err = signature
                .verify(key_pair.public_key(), message)
                .expect_err("malformed Ed25519 R must fail through generic verification");
            assert!(
                matches!(err, Error::BadSignature),
                "{label} R produced unexpected error: {err:?}"
            );
        }
    }
    #[test]
    fn signature_of_verify_rejects_malformed_ed25519_r_before_backend() {
        let key_pair = KeyPair::try_from_seed(vec![0x47; 32], Algorithm::Ed25519)
            .expect("seeded Ed25519 typed keypair");
        let valid_signature =
            SignatureOf::<()>::try_new(key_pair.private_key(), &()).expect("typed signature");
        valid_signature
            .verify(key_pair.public_key(), &())
            .expect("valid typed signature verifies before mutation");
        for (label, replacement_r) in [
            ("small-order", ED25519_SMALL_ORDER_R),
            ("noncanonical", ED25519_NONCANONICAL_R),
        ] {
            let mut payload = valid_signature.payload().to_vec();
            payload[..replacement_r.len()].copy_from_slice(&replacement_r);
            let signature = SignatureOf::<()>::from_signature(Signature::from_bytes(&payload));
            let err = signature
                .verify(key_pair.public_key(), &())
                .expect_err("malformed Ed25519 R must fail through typed verification");
            assert!(
                matches!(err, Error::BadSignature),
                "{label} R produced unexpected typed error: {err:?}"
            );
        }
    }
    #[test]
    fn signature_try_from_bytes_rejects_empty_payload() {
        let err = Signature::try_from_bytes(&[]).expect_err("empty signature must fail closed");
        assert!(
            err.to_string().contains("empty"),
            "unexpected empty signature error: {err}"
        );
    }
    #[test]
    fn signature_try_from_bytes_rejects_all_zero_payload() {
        let err =
            Signature::try_from_bytes(&[0u8; 64]).expect_err("all-zero signature must fail closed");
        assert!(
            err.to_string().contains("all zero"),
            "unexpected all-zero signature error: {err}"
        );
    }
    #[test]
    fn signature_norito_try_deserialize_rejects_empty_payload() {
        let signature = Signature::from_bytes(&[]);
        let framed = norito::core::to_bytes(&signature).expect("frame empty signature");
        let archived =
            norito::from_bytes::<Signature>(&framed).expect("archive empty signature fixture");
        let err = <Signature as norito::core::DeserializePayload>::try_deserialize(archived)
            .expect_err("empty Norito signature must fail closed");
        assert!(
            err.to_string().contains("empty"),
            "unexpected empty Norito signature error: {err}"
        );
    }
    #[test]
    fn signature_norito_try_deserialize_rejects_all_zero_payload() {
        let signature = Signature::from_bytes(&[0u8; 64]);
        let framed = norito::core::to_bytes(&signature).expect("frame all-zero signature");
        let archived =
            norito::from_bytes::<Signature>(&framed).expect("archive all-zero signature fixture");
        let err = <Signature as norito::core::DeserializePayload>::try_deserialize(archived)
            .expect_err("all-zero Norito signature must fail closed");
        assert!(
            err.to_string().contains("all zero"),
            "unexpected all-zero Norito signature error: {err}"
        );
    }
    #[test]
    fn signature_decode_from_slice_rejects_empty_payload() {
        use norito::codec::Encode as _;
        let signature = Signature::from_bytes(&[]);
        let bytes = signature.encode();
        let err = <Signature as norito::core::DecodeFromSlice>::decode_from_slice(&bytes)
            .expect_err("empty bare signature must fail closed");
        assert!(
            err.to_string().contains("empty"),
            "unexpected empty bare signature error: {err}"
        );
    }
    #[test]
    fn signature_decode_from_slice_rejects_all_zero_payload() {
        use norito::codec::Encode as _;
        let signature = Signature::from_bytes(&[0u8; 64]);
        let bytes = signature.encode();
        let err = <Signature as norito::core::DecodeFromSlice>::decode_from_slice(&bytes)
            .expect_err("all-zero bare signature must fail closed");
        assert!(
            err.to_string().contains("all zero"),
            "unexpected all-zero bare signature error: {err}"
        );
    }
    #[test]
    fn borrowed_signature_validation_has_the_same_exact_payload_policy() {
        for bytes in [Vec::new(), vec![0; 64], vec![7; 64], vec![0, 0, 1]] {
            assert_eq!(
                Signature::validate_payload(&bytes).is_ok(),
                Signature::try_from_bytes(&bytes).is_ok()
            );
        }
    }

    #[test]
    fn signature_try_from_bytes_accepts_nonzero_payload() {
        let signature =
            Signature::try_from_bytes(&[0x11u8; 64]).expect("nonzero signature payload");
        assert_eq!(signature.payload(), &[0x11u8; 64]);
    }
    #[test]
    fn canonical_unpacked_signature_decode_uses_exact_fallible_storage() {
        let payload = [0x11_u8; 64];
        let mut bytes = Vec::with_capacity(8 + payload.len() * 9);
        bytes.extend_from_slice(&u64::try_from(payload.len()).unwrap().to_le_bytes());
        for byte in payload {
            bytes.extend_from_slice(&1_u64.to_le_bytes());
            bytes.push(byte);
        }
        let _unpacked_flags = norito::core::DecodeFlagsGuard::enter(0);
        let limits = |allocated| {
            norito::core::DecodeLimits::new(
                usize::MAX,
                usize::MAX,
                usize::MAX,
                allocated,
                usize::MAX,
            )
        };
        let (decoded, usage) =
            norito::core::with_decode_limits_measured(limits(payload.len()), || {
                <Signature as norito::core::DecodeFromSlice>::decode_from_slice(&bytes)
            });
        let (decoded, used) = decoded.expect("exact canonical unpacked allocation");
        assert_eq!(decoded.payload(), payload);
        assert_eq!(used, bytes.len());
        assert_eq!(usage.total_allocated_bytes(), payload.len());

        let (denied, usage) =
            norito::core::with_decode_limits_measured(limits(payload.len() - 1), || {
                <Signature as norito::core::DecodeFromSlice>::decode_from_slice(&bytes)
            });
        assert!(denied.is_err());
        assert!(usage.total_allocated_bytes() < payload.len());

        let sequence_limited = norito::core::DecodeLimits::new(
            payload.len() - 1,
            usize::MAX,
            usize::MAX,
            usize::MAX,
            usize::MAX,
        );
        let error = norito::core::with_decode_limits(sequence_limited, || {
            <Signature as norito::core::DecodeFromSlice>::decode_from_slice(&bytes)
        })
        .expect_err("canonical unpacked decode must enforce the sequence-element ceiling");
        assert!(matches!(
            error,
            norito::core::Error::SequenceLengthExceeded {
                length: 64,
                limit: 63
            }
        ));

        let archived = norito::core::archived_from_slice::<Signature>(&bytes)
            .expect("sized canonical unpacked signature marker");
        let context = norito::core::PayloadCtxGuard::enter(archived.bytes());
        let error = norito::core::with_decode_limits(sequence_limited, || {
            <Signature as norito::core::DeserializePayload<'_>>::try_deserialize(archived.as_ref())
        })
        .expect_err("canonical unpacked pointer decode must enforce the sequence-element ceiling");
        assert!(matches!(
            error,
            norito::core::Error::SequenceLengthExceeded {
                length: 64,
                limit: 63
            }
        ));

        drop(context);
        let mut raw = Vec::with_capacity(8 + payload.len());
        raw.extend_from_slice(&u64::try_from(payload.len()).unwrap().to_le_bytes());
        raw.extend_from_slice(&payload);
        assert!(
            <Signature as norito::core::DecodeFromSlice>::decode_from_slice(&raw).is_err(),
            "raw length-plus-payload signature bytes are not canonical V1"
        );
        let archived = norito::core::archived_from_slice::<Signature>(&raw)
            .expect("sized raw signature marker");
        let _context = norito::core::PayloadCtxGuard::enter(archived.bytes());
        assert!(
            <Signature as norito::core::DeserializePayload<'_>>::try_deserialize(archived.as_ref())
                .is_err(),
            "pointer decoding must reject raw length-plus-payload signature bytes"
        );
    }
    #[test]
    #[cfg(feature = "sm")]
    fn signature_verify_rejects_malformed_sm2_payload_as_bad_signature() {
        let key_pair =
            KeyPair::try_from_seed(vec![0x45; 32], Algorithm::Sm2).expect("seeded SM2 keypair");
        let mut payload = [0u8; crate::Sm2Signature::LENGTH];
        payload[crate::Sm2Signature::LENGTH - 1] = 1;
        let signature = Signature::from_bytes(&payload);
        let err = signature
            .verify(key_pair.public_key(), b"message")
            .expect_err("malformed SM2 signature payload must fail closed");
        assert!(matches!(err, Error::BadSignature));
    }
    #[test]
    #[cfg(feature = "json")]
    fn signature_serialized_representation() {
        let input = norito::json!(
            "3A7991AF1ABB77F3FD27CC148404A6AE4439D095A63591B77C788D53F708A02A1509A611AD6D97B01D871E58ED00C8FD7C3917B6CA61A8C2833A19E000AAC2E4"
        );
        let signature: Signature = norito::json::from_value(input.clone()).unwrap();
        assert_eq!(norito::json::to_value(&signature).unwrap(), input);
    }
    #[test]
    fn signature_from_hex_simply_reproduces_the_data() {
        let payload = "3a7991af1abb77f3fd27cc148404a6ae4439d095a63591b77c788d53f708a02a1509a611ad6d97b01d871e58ed00c8fd7c3917b6ca61a8c2833a19e000aac2e4";
        let value = Signature::from_hex(payload).unwrap();
        assert_eq!(value.payload.as_ref(), &hex::decode(payload).unwrap());
    }
    #[test]
    #[cfg(feature = "json")]
    fn signature_json_rejects_empty_payload() {
        let input = norito::json!("");
        let err = norito::json::from_value::<Signature>(input)
            .expect_err("JSON signature decoding must reject empty payloads");
        assert!(
            err.to_string().contains("empty"),
            "unexpected empty JSON signature error: {err}"
        );
    }
    #[test]
    #[cfg(feature = "json")]
    fn signature_json_rejects_all_zero_payload() {
        let input = norito::json!("00".repeat(64));
        let err = norito::json::from_value::<Signature>(input)
            .expect_err("JSON signature decoding must reject all-zero payloads");
        assert!(
            err.to_string().contains("all zero"),
            "unexpected JSON signature error: {err}"
        );
    }
    #[test]
    fn signature_try_from_hex_rejects_empty_payload() {
        let err = Signature::try_from_hex("").expect_err("empty hex signature must fail closed");
        assert!(
            err.to_string().contains("empty"),
            "unexpected empty signature error: {err}"
        );
    }
    #[test]
    fn signature_try_from_hex_rejects_all_zero_payload() {
        let err = Signature::try_from_hex("00".repeat(64))
            .expect_err("all-zero hex signature must fail closed");
        assert!(
            err.to_string().contains("all zero"),
            "unexpected all-zero signature error: {err}"
        );
    }
    #[test]
    #[cfg(feature = "json")]
    fn signature_of_json_rejects_empty_payload() {
        let input = norito::json!("");
        let err = norito::json::from_value::<SignatureOf<()>>(input)
            .expect_err("typed JSON signature decoding must reject empty payloads");
        assert!(
            err.to_string().contains("empty"),
            "unexpected empty typed JSON signature error: {err}"
        );
    }
    #[test]
    #[cfg(feature = "json")]
    fn signature_of_json_rejects_all_zero_payload() {
        let input = norito::json!("00".repeat(64));
        let err = norito::json::from_value::<SignatureOf<()>>(input)
            .expect_err("typed JSON signature decoding must reject all-zero payloads");
        assert!(
            err.to_string().contains("all zero"),
            "unexpected all-zero typed JSON signature error: {err}"
        );
    }
    #[test]
    #[cfg(feature = "rand")]
    fn signature_of_roundtrip() {
        use norito::codec::{Decode, Encode};
        let key_pair = checked_random_keypair(Algorithm::Ed25519);
        let hash = HashOf::new(&());
        let sig = SignatureOf::try_from_hash(key_pair.private_key(), hash)
            .expect("sign checked SignatureOf roundtrip fixture");
        let bytes = sig.encode();
        // Decode inner Signature from the same bare codec payload.
        let decoded_sig = Signature::decode(&mut &bytes[..]).expect("decode inner signature");
        let decoded = SignatureOf::<()>(decoded_sig, PhantomData);
        assert_eq!(sig, decoded);
    }
    #[test]
    fn signature_norito_roundtrip_preserves_payload() {
        use norito::{
            DeserializePayload,
            codec::{Decode, Encode},
            core::DecodeFromSlice as _,
        };
        let payload = (0u8..32).collect::<Vec<_>>();
        let signature = Signature::from_bytes(&payload);
        let bytes = signature.encode();
        let mut cursor = &bytes[..];
        let decoded_codec = Signature::decode(&mut cursor).expect("codec decode");
        assert_eq!(decoded_codec, signature);
        let framed = norito::core::to_bytes(&signature).expect("frame signature payload");
        let archived = norito::from_bytes::<Signature>(&framed).expect("archived signature");
        let decoded = Signature::deserialize(archived);
        assert_eq!(decoded, signature);
        let inner_payload = &framed[std::mem::size_of::<norito::core::Header>()..];
        let (decoded_from_slice, used) =
            Signature::decode_from_slice(inner_payload).expect("slice decode");
        assert_eq!(used, inner_payload.len());
        assert_eq!(decoded_from_slice, signature);
        norito::core::reset_decode_state();
    }
    #[test]
    fn signature_of_try_deserialize_preserves_compact_const_vec_payload() {
        let payload = (0u8..64).collect::<Vec<_>>();
        let typed = SignatureOf::<()>::from_signature(Signature::from_bytes(&payload));
        let framed = norito::core::to_bytes(&typed).expect("frame typed signature");
        let archived =
            norito::from_bytes::<SignatureOf<()>>(&framed).expect("archived typed signature");
        let decoded =
            <SignatureOf<()> as norito::core::DeserializePayload>::try_deserialize(archived)
                .expect("typed signature decodes");
        assert_eq!(decoded, typed);
        norito::core::reset_decode_state();
    }
    #[test]
    fn signature_of_try_deserialize_rejects_empty_payload() {
        let typed = SignatureOf::<()>::from_signature(Signature::from_bytes(&[]));
        let framed = norito::core::to_bytes(&typed).expect("frame empty typed signature");
        let archived =
            norito::from_bytes::<SignatureOf<()>>(&framed).expect("archived typed signature");
        let err = <SignatureOf<()> as norito::core::DeserializePayload>::try_deserialize(archived)
            .expect_err("empty typed signature must fail closed");
        assert!(
            err.to_string().contains("empty"),
            "unexpected empty typed signature error: {err}"
        );
        norito::core::reset_decode_state();
    }
    #[test]
    fn signature_of_try_deserialize_rejects_all_zero_payload() {
        let typed = SignatureOf::<()>::from_signature(Signature::from_bytes(&[0u8; 64]));
        let framed = norito::core::to_bytes(&typed).expect("frame all-zero typed signature");
        let archived =
            norito::from_bytes::<SignatureOf<()>>(&framed).expect("archived typed signature");
        let err = <SignatureOf<()> as norito::core::DeserializePayload>::try_deserialize(archived)
            .expect_err("all-zero typed signature must fail closed");
        assert!(
            err.to_string().contains("all zero"),
            "unexpected all-zero typed signature error: {err}"
        );
        norito::core::reset_decode_state();
    }
    #[test]
    fn signature_of_decode_from_slice_rejects_empty_payload() {
        use norito::codec::Encode as _;
        let typed = SignatureOf::<()>::from_signature(Signature::from_bytes(&[]));
        let bytes = typed.encode();
        let err = <SignatureOf<()> as norito::core::DecodeFromSlice>::decode_from_slice(&bytes)
            .expect_err("empty bare typed signature must fail closed");
        assert!(
            err.to_string().contains("empty"),
            "unexpected empty bare typed signature error: {err}"
        );
    }
    #[test]
    fn signature_of_decode_from_slice_rejects_all_zero_payload() {
        use norito::codec::Encode as _;
        let typed = SignatureOf::<()>::from_signature(Signature::from_bytes(&[0u8; 64]));
        let bytes = typed.encode();
        let err = <SignatureOf<()> as norito::core::DecodeFromSlice>::decode_from_slice(&bytes)
            .expect_err("all-zero bare typed signature must fail closed");
        assert!(
            err.to_string().contains("all zero"),
            "unexpected all-zero bare typed signature error: {err}"
        );
    }
    #[test]
    fn signature_of_from_signature_wraps_payload() {
        let payload = (0u8..64).collect::<Vec<_>>();
        let signature = Signature::from_bytes(&payload);
        let typed = SignatureOf::<()>::from_signature(signature.clone());
        assert_eq!(Signature::from(typed), signature);
    }
    #[test]
    fn signature_vec_roundtrip_via_norito() {
        use norito::DeserializePayload;
        let payload = (0u8..16).collect::<Vec<_>>();
        let signature = Signature::from_bytes(&payload);
        let values = vec![signature.clone()];
        let bytes = norito::core::to_bytes(&values).expect("encode signature vec");
        println!("signature vec encoded bytes {bytes:02X?}");
        let archived = norito::core::from_bytes::<Vec<Signature>>(&bytes)
            .expect("decode signature vec header");
        let decoded = Vec::<Signature>::deserialize(archived);
        let payload = decoded[0].payload();
        println!("decoded signature payload {payload:02X?}");
        assert_eq!(decoded, values);
    }
}
