//! Public-key decoding with fixed validation failures and exact retained storage.
//!
//! The binary element-sequence codec owns framing; this module owns only key
//! validation and the compact destination. The bounded stack scratch below is
//! not an execution-owner stack reservation. JSON's source String and outer
//! diagnostic adapters have separate custody and are not closed by this module.

use super::{Algorithm, ConstVec, PublicKey, PublicKeyCompact, multihash, signature};
use norito::core::{DecodeFromSlice, DeserializePayload, Error};

fn invalid_key() -> Error {
    Error::InvalidValue {
        context: "public key",
    }
}

pub fn validate(algorithm: Algorithm, payload: &[u8]) -> Result<(), Error> {
    let valid = match algorithm {
        Algorithm::Ed25519 => {
            signature::ed25519::Ed25519Sha512::parse_public_key_uncached_for_decode(payload)
                .map(drop)
                .is_ok()
        }
        Algorithm::Secp256k1 => {
            signature::secp256k1::EcdsaSecp256k1Sha256::validate_public_key_for_decode(payload)
                .is_ok()
        }
        Algorithm::MlDsa => signature::mldsa::validate_public_key(payload).is_ok(),
        #[cfg(feature = "gost")]
        Algorithm::Gost3410_2012_256ParamSetA
        | Algorithm::Gost3410_2012_256ParamSetB
        | Algorithm::Gost3410_2012_256ParamSetC
        | Algorithm::Gost3410_2012_512ParamSetA
        | Algorithm::Gost3410_2012_512ParamSetB => {
            signature::gost::validate_public_key(algorithm, payload).is_ok()
        }
        #[cfg(feature = "bls")]
        Algorithm::BlsNormal | Algorithm::BlsSmall => {
            super::bls_decode_cache::validate(algorithm, payload).is_ok()
        }
        #[cfg(feature = "sm")]
        Algorithm::Sm2 => super::sm::verification::BorrowedKey::parse(payload).is_ok(),
        #[cfg(not(feature = "bls"))]
        Algorithm::BlsNormal | Algorithm::BlsSmall => {
            return Err(Error::UnsupportedFeature(algorithm.as_static_str()));
        }
        #[cfg(not(feature = "gost"))]
        Algorithm::Gost3410_2012_256ParamSetA
        | Algorithm::Gost3410_2012_256ParamSetB
        | Algorithm::Gost3410_2012_256ParamSetC
        | Algorithm::Gost3410_2012_512ParamSetA
        | Algorithm::Gost3410_2012_512ParamSetB => {
            return Err(Error::UnsupportedFeature(algorithm.as_static_str()));
        }
        #[cfg(not(feature = "sm"))]
        Algorithm::Sm2 => return Err(Error::UnsupportedFeature(algorithm.as_static_str())),
    };
    valid.then_some(()).ok_or_else(invalid_key)
}

/// Preserve the canonical compact owner's nominal decode-work admission even
/// when a caller already owns its initialized physical backing.
pub fn reserve_compact_decode_backing(payload_bytes: usize) -> Result<usize, Error> {
    let allocation_bytes = payload_bytes
        .checked_add(1)
        .ok_or(Error::AllocationFailed { bytes: u64::MAX })?;
    norito::core::reserve_decode_allocation(allocation_bytes)?;
    Ok(allocation_bytes)
}

impl PublicKeyCompact {
    #[allow(unsafe_code)]
    pub(super) fn try_new_for_decode(
        algorithm: Algorithm,
        payload: &[u8],
    ) -> Result<Self, norito::core::Error> {
        let allocation_bytes = reserve_compact_decode_backing(payload.len())?;
        let layout = std::alloc::Layout::array::<u8>(allocation_bytes)
            .map_err(|_| norito::core::Error::AllocationFailed { bytes: u64::MAX })?;
        // SAFETY: `layout` is non-zero and valid for `allocation_bytes` bytes.
        let allocation = unsafe { std::alloc::alloc(layout) };
        let allocation = core::ptr::NonNull::new(allocation).ok_or_else(|| {
            norito::core::Error::AllocationFailed {
                bytes: u64::try_from(allocation_bytes).unwrap_or(u64::MAX),
            }
        })?;
        // SAFETY: the exact allocation owns `allocation_bytes`; write its tag
        // and copy the disjoint payload tail before creating the boxed slice.
        unsafe {
            allocation.as_ptr().write(Self::algorithm_tag(algorithm));
            core::ptr::copy_nonoverlapping(
                payload.as_ptr(),
                allocation.as_ptr().add(1),
                payload.len(),
            );
            let slice = core::ptr::slice_from_raw_parts_mut(allocation.as_ptr(), allocation_bytes);
            Ok(Self {
                algorithm_and_payload: ConstVec::new(Box::from_raw(slice)),
            })
        }
    }
    #[allow(unsafe_code)]
    fn try_new_from_canonical_hex_for_decode(
        algorithm: Algorithm,
        payload_hex: &str,
    ) -> Result<Self, norito::core::Error> {
        let payload_bytes = payload_hex.len() / 2;
        let allocation_bytes = reserve_compact_decode_backing(payload_bytes)?;
        let layout = std::alloc::Layout::array::<u8>(allocation_bytes)
            .map_err(|_| norito::core::Error::AllocationFailed { bytes: u64::MAX })?;
        // SAFETY: the exact destination was admitted before this allocation;
        // null is rejected before ownership.
        let allocation = unsafe { std::alloc::alloc(layout) };
        let allocation = core::ptr::NonNull::new(allocation).ok_or_else(|| {
            norito::core::Error::AllocationFailed {
                bytes: u64::try_from(allocation_bytes).unwrap_or(u64::MAX),
            }
        })?;
        // SAFETY: every payload pair is canonical and initializes one disjoint
        // byte; on failure the raw allocation is reclaimed with its exact layout.
        unsafe { allocation.as_ptr().write(Self::algorithm_tag(algorithm)) };
        for (index, pair) in payload_hex.as_bytes().chunks_exact(2).enumerate() {
            let Some(byte) = multihash::decode_public_key_payload_byte(pair) else {
                // SAFETY: `allocation` still has the exact `layout` above.
                unsafe { std::alloc::dealloc(allocation.as_ptr(), layout) };
                return Err(invalid_key());
            };
            // SAFETY: `index < payload_bytes`, so the tag-offset slot is valid.
            unsafe { allocation.as_ptr().add(index + 1).write(byte) };
        }
        // SAFETY: all `allocation_bytes` bytes are initialized and uniquely owned.
        let compact = unsafe {
            let slice = core::ptr::slice_from_raw_parts_mut(allocation.as_ptr(), allocation_bytes);
            Self {
                algorithm_and_payload: ConstVec::new(Box::from_raw(slice)),
            }
        };
        // The owned allocation always includes the initialized tag at index zero.
        validate(algorithm, &compact.algorithm_and_payload[1..])?;
        Ok(compact)
    }
}

/// The sole compact-byte parser and validator, with a caller-selected owner.
/// Fixed scratch never becomes a retained allocation. Ordinary decoding and the
/// prepared destination choose their owner only after the same validation.
pub fn with_decoded_compact<R, E>(
    bytes: &[u8],
    exact: bool,
    retain: impl FnOnce(Algorithm, &[u8]) -> Result<R, E>,
) -> Result<(R, usize), E>
where
    E: From<Error>,
{
    let mut scratch = [0; super::MAX_PUBLIC_KEY_PAYLOAD_BYTES + 1];
    let (length, used) = norito::core::decode_byte_element_sequence_into(bytes, &mut scratch)?;
    if exact && used != bytes.len() {
        return Err(Error::LengthMismatch.into());
    }
    let (&tag, payload) = scratch[..length]
        .split_first()
        .ok_or(Error::LengthMismatch)?;
    let algorithm = Algorithm::try_from(tag)
        .map_err(|()| Error::invalid_tag("PublicKeyCompact::algorithm", tag))?;
    validate(algorithm, payload)?;
    retain(algorithm, payload).map(|key| (key, used))
}

fn decode_compact(bytes: &[u8], exact: bool) -> Result<(PublicKeyCompact, usize), Error> {
    with_decoded_compact(bytes, exact, PublicKeyCompact::try_new_for_decode)
}

impl<'de> DeserializePayload<'de> for PublicKeyCompact {
    fn deserialize(archived: &'de norito::core::Archived<Self>) -> Self {
        Self::try_deserialize(archived).expect("PublicKeyCompact decode")
    }
    fn try_deserialize(archived: &'de norito::core::Archived<Self>) -> Result<Self, Error> {
        let bytes =
            norito::core::payload_slice_from_ptr(core::ptr::from_ref(archived).cast::<u8>())?;
        decode_compact(bytes, true).map(|(key, _)| key)
    }
}
impl<'a> DecodeFromSlice<'a> for PublicKeyCompact {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), Error> {
        decode_compact(bytes, false)
    }
}

impl PublicKey {
    /// Validate and retain a public key under active decode resource accounting.
    ///
    /// Every algorithm uses its shared canonical relation with fixed rejection
    /// custody. BLS may reuse an exact success in fixed thread-local storage.
    /// Neither successful nor rejected validation allocates. Only the compact
    /// key's exact retained allocation is charged and created fallibly.
    /// Ordinary callers should continue to use [`Self::from_bytes`].
    ///
    /// # Errors
    ///
    /// Returns a decode-resource error when the active budget or allocator
    /// rejects the compact destination, a fixed parse error for invalid encoding,
    /// or `UnsupportedFeature` when the known algorithm lacks a local parser.
    #[doc(hidden)]
    pub fn from_bytes_for_decode(
        algorithm: Algorithm,
        payload: &[u8],
    ) -> Result<Self, norito::core::Error> {
        validate(algorithm, payload)?;
        PublicKeyCompact::try_new_for_decode(algorithm, payload).map(Self)
    }

    /// Decode one canonical bare multihash literal under active resource limits.
    ///
    /// This borrows the hexadecimal source, validates the key without using
    /// parse caches where the selected backend supports that path, and creates
    /// the retained compact key through the fallible exact-allocation seam.
    ///
    /// # Errors
    ///
    /// Returns a resource-limit error when the active decode budget or
    /// allocator rejects the key, and a fixed parse error for malformed input.
    #[doc(hidden)]
    pub fn from_canonical_str_for_decode(value: &str) -> Result<Self, norito::core::Error> {
        let decoded = multihash::decode_public_key_str_borrowed(value).ok_or_else(invalid_key)?;
        PublicKeyCompact::try_new_from_canonical_hex_for_decode(
            decoded.algorithm,
            decoded.payload_hex,
        )
        .map(Self)
    }
}
