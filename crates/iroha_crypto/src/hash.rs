use crate::{ParseError, hex_decode};
use blake2::{
    Blake2b,
    digest::{Digest, consts::U32},
};
use derive_more::{Debug, Deref, DerefMut, Display};
use iroha_schema::{IntoSchema, TypeId};
#[cfg(feature = "json")]
use norito::json::JsonKeyCodec;
#[cfg(feature = "json")]
use norito::json::{self, FastJsonWrite, JsonDeserialize};
#[cfg(feature = "json")]
use norito::literal;
use sha2::Sha256;
use sha3::Keccak256;
use std::{borrow::ToOwned as _, format, hash, marker::PhantomData, str::FromStr, string::String};
use zeroize::Zeroize;
/// Hash of Iroha entities. Currently supports only blake2b-32.
/// The least significant bit of hash is set to 1.
///
/// The marker is a logical invariant rather than a Rust validity invariant: the byte-array storage
/// deliberately has no niche or invalid bit pattern. This lets untrusted archived bytes be
/// inspected and rejected safely before an owned `Hash` is constructed.
#[derive(Debug, Display, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, TypeId)]
#[display("{}", hex::encode(self.as_ref()))]
#[debug("{}", hex::encode(self.as_ref()))]
#[repr(transparent)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_crypto::hash::Hash")]
pub struct Hash([u8; Self::LENGTH]);
impl Zeroize for Hash {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
impl Hash {
    /// Length of hash
    pub const LENGTH: usize = 32;
    /// Wrap the given bytes; they must be prehashed with Blake2b-32.
    pub fn prehashed(mut hash: [u8; Self::LENGTH]) -> Self {
        hash[Self::LENGTH - 1] |= 1;
        Self(hash)
    }
    /// Check if least significant bit of `[u8; Hash::LENGTH]` is 1
    fn is_lsb_1(hash: &[u8; Self::LENGTH]) -> bool {
        hash[Self::LENGTH - 1] & 1 == 1
    }
    /// Accept an already marked hash without changing its bytes.
    ///
    /// Returns `None` if the Iroha hash marker is absent. This checks the wire
    /// representation only; it does not authenticate the digest's preimage.
    #[must_use]
    pub fn from_marked_bytes(hash: [u8; Self::LENGTH]) -> Option<Self> {
        Self::is_lsb_1(&hash).then_some(Self(hash))
    }
    fn decode_archived(
        archived: &norito::core::Archived<Self>,
    ) -> Result<Self, norito::core::Error> {
        let ptr = core::ptr::from_ref(archived).cast::<u8>();
        let mut offset = 0;
        let bytes = norito::core::decode_context_byte_array::<{ Self::LENGTH }>(ptr, &mut offset)?;
        norito::core::finish_context_fields(ptr, offset)?;
        Self::from_marked_bytes(bytes).ok_or_else(|| norito::core::Error::InvalidValue {
            context: "hash lsb",
        })
    }
}
/// Compute raw SHA-256 bytes without Iroha hash marker semantics.
#[must_use]
pub fn sha256(bytes: impl AsRef<[u8]>) -> [u8; Hash::LENGTH] {
    Sha256::digest(bytes.as_ref()).into()
}
/// Compute raw BLAKE3-256 bytes without Iroha hash marker semantics.
#[must_use]
pub fn blake3_256(bytes: impl AsRef<[u8]>) -> [u8; Hash::LENGTH] {
    *blake3::hash(bytes.as_ref()).as_bytes()
}
/// Compute raw SHA-256 bytes from a reader without buffering the complete input.
///
/// The reader is rejected after at most one buffer beyond `max_bytes`. This makes
/// the helper suitable for hashing attacker-influenced persisted artifacts while
/// retaining a hard input-size bound.
///
/// # Errors
///
/// Returns the reader's I/O error, or [`std::io::ErrorKind::InvalidData`] when
/// the observed byte count overflows or exceeds `max_bytes`.
pub fn sha256_reader_bounded(
    mut reader: impl std::io::Read,
    max_bytes: u64,
) -> std::io::Result<([u8; Hash::LENGTH], u64)> {
    const BUFFER_BYTES: usize = 64 * 1024;
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = zeroize::Zeroizing::new(vec![0_u8; BUFFER_BYTES].into_boxed_slice());
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(read).expect("read length fits u64"))
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "SHA-256 input size overflow",
                )
            })?;
        if total > max_bytes {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("SHA-256 input exceeds {max_bytes} byte limit"),
            ));
        }
        Digest::update(&mut hasher, &buffer[..read]);
    }
    Ok((hasher.finalize().into(), total))
}
/// Compute raw Keccak-256 bytes without Iroha hash marker semantics.
#[must_use]
pub fn keccak256(bytes: impl AsRef<[u8]>) -> [u8; Hash::LENGTH] {
    Keccak256::digest(bytes.as_ref()).into()
}
/// Compute raw Keccak-256 over borrowed chunks without collecting their concatenation.
///
/// The first input error is returned unchanged; subsequent chunks are never requested.
/// This permits a caller to stream checked key payloads without allocating a key list or
/// a preimage buffer. The digest has no Iroha hash marker semantics.
///
/// # Errors
/// Returns the first error produced by the input iterator.
pub fn try_keccak256_from_chunks<E>(
    chunks: impl IntoIterator<Item = Result<impl AsRef<[u8]>, E>>,
) -> Result<[u8; Hash::LENGTH], E> {
    let mut hasher = Keccak256::new();
    for chunk in chunks {
        Digest::update(&mut hasher, chunk?.as_ref());
    }
    Ok(hasher.finalize().into())
}
impl Hash {
    /// Hash the given bytes.
    #[must_use]
    pub fn new(bytes: impl AsRef<[u8]>) -> Self {
        let mut hasher = Blake2b256::new();
        Digest::update(&mut hasher, bytes.as_ref());
        finalize_blake2b(hasher)
    }
    /// Hash the concatenation of the provided byte chunks without first
    /// materializing them into one contiguous buffer.
    #[must_use]
    pub fn new_from_chunks(chunks: &[&[u8]]) -> Self {
        let mut hasher = Blake2b256::new();
        for chunk in chunks {
            Digest::update(&mut hasher, chunk);
        }
        finalize_blake2b(hasher)
    }
    /// Hash bytes emitted by a fallible streaming producer.
    ///
    /// The callback writes directly into the incremental hasher, so callers do
    /// not need to materialize a response-sized concatenation buffer.
    ///
    /// # Errors
    ///
    /// Returns the callback's I/O error without producing a partial digest.
    pub fn new_from_writer(
        write: impl FnOnce(&mut dyn std::io::Write) -> std::io::Result<()>,
    ) -> std::io::Result<Self> {
        let mut writer = HashWriter::new();
        write(&mut writer)?;
        Ok(writer.finalize())
    }
    /// Hash bytes from a reader without buffering the complete input.
    ///
    /// Reading stops with [`std::io::ErrorKind::InvalidData`] once the input
    /// exceeds `max_bytes`, including when the byte counter would overflow.
    ///
    /// # Errors
    ///
    /// Returns the reader's I/O error or an invalid-data error when the bound is exceeded.
    pub fn new_from_reader_bounded(
        mut reader: impl std::io::Read,
        max_bytes: u64,
    ) -> std::io::Result<(Self, u64)> {
        const BUFFER_BYTES: usize = 64 * 1024;
        let mut writer = HashWriter::new();
        let mut total = 0_u64;
        let mut buffer = vec![0_u8; BUFFER_BYTES].into_boxed_slice();
        loop {
            let read = std::io::Read::read(&mut reader, &mut buffer)?;
            if read == 0 {
                break;
            }
            total = total
                .checked_add(u64::try_from(read).expect("read length fits u64"))
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Blake2b-32 input size overflow",
                    )
                })?;
            if total > max_bytes {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Blake2b-32 input exceeds {max_bytes} byte limit"),
                ));
            }
            std::io::Write::write_all(&mut writer, &buffer[..read])?;
        }
        Ok((writer.finalize(), total))
    }
}
type Blake2b256 = Blake2b<U32>;
fn finalize_blake2b(hasher: Blake2b256) -> Hash {
    let hash: [u8; Hash::LENGTH] = hasher.finalize().into();
    Hash::prehashed(hash)
}
struct HashWriter {
    hasher: Blake2b256,
}
impl HashWriter {
    fn new() -> Self {
        Self {
            hasher: Blake2b256::new(),
        }
    }
    fn finalize(self) -> Hash {
        finalize_blake2b(self.hasher)
    }
}
impl std::io::Write for HashWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        Digest::update(&mut self.hasher, buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
#[cfg(feature = "json")]
fn ensure_uppercase_hex(candidate: &str, literal: &str) -> Result<(), json::Error> {
    if candidate.chars().any(|c| c.is_ascii_lowercase()) {
        return Err(json::Error::Message(format!(
            "hash literal `{literal}` must use uppercase hex digits"
        )));
    }
    Ok(())
}
#[cfg(feature = "json")]
fn parse_hash_literal(value: &str) -> Result<Hash, json::Error> {
    let body = literal::parse("hash", value)?;
    ensure_uppercase_hex(body, value)?;
    Hash::from_str(body).map_err(|err| json::Error::Message(err.to_string()))
}
impl From<Hash> for [u8; Hash::LENGTH] {
    #[inline]
    fn from(hash: Hash) -> Self {
        hash.0
    }
}
impl AsRef<[u8; Hash::LENGTH]> for Hash {
    #[inline]
    fn as_ref(&self) -> &[u8; Hash::LENGTH] {
        &self.0
    }
}
#[cfg(feature = "json")]
impl FastJsonWrite for Hash {
    fn write_json(&self, out: &mut String) {
        let body = hex::encode_upper(self.as_ref());
        let literal = literal::format("hash", &body);
        json::write_json_string(&literal, out);
    }
    fn write_json_to(
        &self,
        out: &mut dyn json::JsonWriteSink,
    ) -> Result<(), json::BoundedJsonError> {
        // The canonical hash literal is fixed-width (32-byte body plus tag and
        // checksum), so this scratch allocation cannot scale with a response.
        let body = hex::encode_upper(self.as_ref());
        let literal = literal::format("hash", &body);
        json::write_json_string_to(&literal, out)
    }
}
#[cfg(feature = "json")]
impl JsonDeserialize for Hash {
    fn json_deserialize(parser: &mut json::Parser<'_>) -> Result<Self, json::Error> {
        let value = parser.parse_string()?;
        parse_hash_literal(&value)
    }
}
#[cfg(feature = "json")]
impl json::JsonObjectKey for Hash {
    fn visit_json_key_text<E>(
        &self,
        mut visitor: impl FnMut(&str) -> Result<(), E>,
    ) -> Result<(), E> {
        let body = hex::encode_upper(self.as_ref());
        let canonical = literal::format("hash", &body);
        visitor(&canonical)
    }
}
#[cfg(feature = "json")]
impl json::JsonObjectKeyOwned for Hash {
    fn from_json_key_text(key: &str) -> Result<Self, json::Error> {
        parse_hash_literal(key)
    }
}
#[cfg(feature = "json")]
impl JsonKeyCodec for Hash {
    fn encode_json_key(&self, out: &mut String) {
        FastJsonWrite::write_json(self, out);
    }
    fn decode_json_key(encoded: &str) -> Result<Self, json::Error> {
        parse_hash_literal(encoded)
    }
}

impl norito::core::SerializePayload for Hash {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), norito::core::Error> {
        writer.write_all(self.as_ref())?;
        Ok(())
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        Some(Self::LENGTH)
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        Some(Self::LENGTH)
    }
}

impl<'de> norito::core::DeserializePayload<'de> for Hash {
    fn deserialize(archived: &'de norito::core::Archived<Self>) -> Self {
        Self::try_deserialize(archived).expect("Hash decode")
    }
    fn try_deserialize(
        archived: &'de norito::core::Archived<Self>,
    ) -> Result<Self, norito::core::Error> {
        Self::decode_archived(archived)
    }
}
impl<'a> norito::core::DecodeFromSlice<'a> for Hash {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        if bytes.len() < Self::LENGTH {
            return Err(norito::core::Error::LengthMismatch);
        }
        let mut b = [0u8; Self::LENGTH];
        b.copy_from_slice(&bytes[..Self::LENGTH]);
        Self::from_marked_bytes(b)
            .map(|hash| (hash, Self::LENGTH))
            .ok_or_else(|| norito::core::Error::InvalidValue {
                context: "hash lsb",
            })
    }
}
impl FromStr for Hash {
    type Err = ParseError;
    fn from_str(key: &str) -> Result<Self, Self::Err> {
        let hash: [u8; Self::LENGTH] = hex_decode(key)?.try_into().map_err(|hash_vec| {
            ParseError(format!(
                "Unable to parse {hash_vec:?} as [u8; {}]",
                Self::LENGTH
            ))
        })?;
        Hash::from_marked_bytes(hash)
            .ok_or_else(|| ParseError("expect least significant bit of hash to be 1".to_owned()))
    }
}
impl IntoSchema for Hash {
    fn type_name() -> String {
        "Hash".to_owned()
    }
    fn update_schema_map(map: &mut iroha_schema::MetaMap) {
        if !map.contains_key::<Self>() {
            <[u8; Self::LENGTH]>::update_schema_map(map);
            map.insert::<Self>(iroha_schema::Metadata::Tuple(
                iroha_schema::UnnamedFieldsMeta {
                    types: vec![core::any::TypeId::of::<[u8; Self::LENGTH]>()],
                },
            ));
        }
    }
}
impl<T> From<HashOf<T>> for Hash {
    fn from(HashOf(hash, _): HashOf<T>) -> Self {
        hash
    }
}
/// Represents hash of Iroha entities like `Block` or `Transaction`. Currently supports only blake2b-32.
#[derive(Debug, Display, Deref, DerefMut, TypeId)]
#[debug("{{ {} {_0} }}", core::any::type_name::<Self>())]
#[display("{_0}")]
#[repr(transparent)]
pub struct HashOf<T>(
    #[deref]
    #[deref_mut]
    Hash,
    PhantomData<T>,
);
impl<T> Clone for HashOf<T> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<T> Copy for HashOf<T> {}
#[allow(clippy::unconditional_recursion)] // False-positive
impl<T> PartialEq for HashOf<T> {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq(&other.0)
    }
}
impl<T> Eq for HashOf<T> {}
impl<T> PartialOrd for HashOf<T> {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl<T> Ord for HashOf<T> {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}
impl<T> hash::Hash for HashOf<T> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}
impl<T> AsRef<[u8; Hash::LENGTH]> for HashOf<T> {
    fn as_ref(&self) -> &[u8; Hash::LENGTH] {
        self.0.as_ref()
    }
}
/// Archived representation of [`HashOf`].
pub type ArchivedHashOf<T> = norito::core::Archived<HashOf<T>>;
impl<T: norito::NoritoSchema> norito::NoritoSchema for HashOf<T> {
    fn nominal_name() -> String {
        norito::schema::identity::generic_name("iroha_crypto::hash::HashOf", &[T::nominal_name()])
    }
}

impl<T> norito::core::SerializePayload for HashOf<T> {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), norito::core::Error> {
        writer.write_all(self.0.as_ref())?;
        Ok(())
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        Some(Hash::LENGTH)
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        Some(Hash::LENGTH)
    }
}

impl<'de, T> norito::core::DeserializePayload<'de> for HashOf<T> {
    fn deserialize(archived: &'de norito::core::Archived<Self>) -> Self {
        Self::try_deserialize(archived).expect("HashOf decode")
    }
    fn try_deserialize(
        archived: &'de norito::core::Archived<Self>,
    ) -> Result<Self, norito::core::Error> {
        let hash =
            <Hash as norito::core::DeserializePayload>::try_deserialize(archived.cast::<Hash>())?;
        Ok(Self(hash, PhantomData))
    }
}
impl<T> HashOf<T> {
    /// Transmutes hash to some specific type. Don't use this method if not required.
    #[inline]
    #[must_use]
    pub(crate) const fn transmute<F>(self) -> HashOf<F> {
        HashOf(self.0, PhantomData)
    }
    /// Adds type information to the hash. Be careful about using this function
    /// since it is not possible to validate the correctness of the conversion.
    /// Prefer creating new hashes with [`HashOf::new`] whenever possible
    #[must_use]
    pub const fn from_untyped_unchecked(hash: Hash) -> Self {
        HashOf(hash, PhantomData)
    }
}
impl<T: norito::codec::Encode> HashOf<T> {
    /// Construct typed hash
    #[must_use]
    pub fn new(value: &T) -> Self {
        Self::try_new(value).expect("typed hash encoding should not fail")
    }
    /// Construct the same typed hash while preserving the original serialization failure.
    ///
    /// The fixed V1 serializer streams directly into the existing hash owner; no encoded
    /// frame or alternate hash domain is constructed.
    ///
    /// # Errors
    /// Returns the serializer's codec or local resource refusal without a partial hash.
    pub fn try_new(value: &T) -> Result<Self, norito::Error> {
        let mut writer = HashWriter::new();
        norito::codec::encode_adaptive_into(value, &mut writer)?;
        Ok(Self(writer.finalize(), PhantomData))
    }
}
impl<T> FromStr for HashOf<T> {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse::<Hash>().map(Self::from_untyped_unchecked)
    }
}
#[cfg(feature = "json")]
impl<T> FastJsonWrite for HashOf<T> {
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
impl<T> JsonDeserialize for HashOf<T> {
    fn json_deserialize(parser: &mut json::Parser<'_>) -> Result<Self, json::Error> {
        Hash::json_deserialize(parser).map(|hash| HashOf(hash, PhantomData))
    }
}
#[cfg(feature = "json")]
impl<T> json::JsonObjectKey for HashOf<T> {
    fn visit_json_key_text<E>(&self, visitor: impl FnMut(&str) -> Result<(), E>) -> Result<(), E> {
        json::JsonObjectKey::visit_json_key_text(&self.0, visitor)
    }
}
#[cfg(feature = "json")]
impl<T> json::JsonObjectKeyOwned for HashOf<T> {
    fn from_json_key_text(key: &str) -> Result<Self, json::Error> {
        <Hash as json::JsonObjectKeyOwned>::from_json_key_text(key)
            .map(|hash| HashOf(hash, PhantomData))
    }
}
#[cfg(feature = "json")]
impl<T> JsonKeyCodec for HashOf<T> {
    fn encode_json_key(&self, out: &mut String) {
        FastJsonWrite::write_json(&self.0, out);
    }
    fn decode_json_key(encoded: &str) -> Result<Self, json::Error> {
        parse_hash_literal(encoded).map(|hash| HashOf(hash, PhantomData))
    }
}
impl<T: IntoSchema> IntoSchema for HashOf<T> {
    fn type_name() -> String {
        format!("HashOf<{}>", T::type_name())
    }
    fn update_schema_map(map: &mut iroha_schema::MetaMap) {
        if !map.contains_key::<Self>() {
            // The referent supplies the name, but only the digest is stored.
            // Traversing T here follows links back into their owning records.
            Hash::update_schema_map(map);
            map.insert::<Self>(iroha_schema::Metadata::Tuple(
                iroha_schema::UnnamedFieldsMeta {
                    types: vec![core::any::TypeId::of::<Hash>()],
                },
            ));
        }
    }
}
// Provide slice-based decoding for HashOf<T> so it can be used inside packed
// sequences and option fields on Norito's bounded decode path.
impl<'a, T> norito::core::DecodeFromSlice<'a> for HashOf<T> {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        let (hash, used) = <Hash as norito::core::DecodeFromSlice>::decode_from_slice(bytes)?;
        Ok((HashOf(hash, PhantomData), used))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn blake2_32b() {
        let mut hasher = Blake2b256::new();
        Digest::update(&mut hasher, hex_literal::hex!("6920616d2064617461"));
        let hash: [u8; Hash::LENGTH] = hasher.finalize().into();
        assert_eq!(
            hash,
            hex_literal::hex!("BA67336EFD6A3DF3A70EEB757860763036785C182FF4CF587541A0068D09F5B2")
        );
    }
    #[test]
    fn sha256_returns_raw_digest_bytes() {
        assert_eq!(
            sha256(b"abc"),
            hex_literal::hex!("BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD")
        );
    }
    #[test]
    fn blake3_256_returns_raw_digest_bytes() {
        assert_eq!(
            blake3_256(b""),
            hex_literal::hex!("AF1349B9F5F9A1A6A0404DEA36DCC9499BCB25C9ADC112B7CC9A93CAE41F3262")
        );
    }
    #[test]
    fn bounded_streaming_sha256_matches_contiguous_digest() {
        let bytes = vec![0x5a; 3 * 64 * 1024 + 17];
        let (digest, size) =
            sha256_reader_bounded(bytes.as_slice(), bytes.len() as u64).expect("bounded hash");
        assert_eq!(digest, sha256(&bytes));
        assert_eq!(size, bytes.len() as u64);
    }
    #[test]
    fn bounded_streaming_sha256_rejects_oversized_input() {
        let err = sha256_reader_bounded(&b"oversized"[..], 8).expect_err("input exceeds limit");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }
    #[test]
    fn bounded_streaming_sha256_preserves_reader_error_after_sensitive_prefix() {
        struct FailingReader(usize);
        impl std::io::Read for FailingReader {
            fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
                self.0 += 1;
                assert_eq!(output.len(), 64 * 1024);
                if self.0 == 1 {
                    output[..17].copy_from_slice(b"sensitive-prefix!");
                    return Ok(17);
                }
                Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "reader-denied",
                ))
            }
        }
        let mut reader = FailingReader(0);
        let error = sha256_reader_bounded(&mut reader, 64 * 1024).unwrap_err();
        assert_eq!(reader.0, 2);
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(error.to_string(), "reader-denied");
        assert!(!format!("{error:?}").contains("sensitive-prefix"));
    }
    #[test]
    fn bounded_streaming_sha256_propagates_reader_unwind_after_sensitive_prefix() {
        struct PanickingReader(usize);
        impl std::io::Read for PanickingReader {
            fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
                self.0 += 1;
                assert_eq!(output.len(), 64 * 1024);
                if self.0 == 1 {
                    output[..17].copy_from_slice(b"sensitive-prefix!");
                    return Ok(17);
                }
                panic!("reader unwind");
            }
        }
        let mut reader = PanickingReader(0);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            sha256_reader_bounded(&mut reader, 64 * 1024)
        }));
        assert!(result.is_err());
        assert_eq!(reader.0, 2);
    }
    #[test]
    fn keccak256_chunks_match_concatenation_across_rate_boundaries() {
        let bytes = [0x9a; 300];
        for boundary in [0, 1, 135, 136, 137, 272, 300] {
            let chunks = [&bytes[..boundary], &[], &bytes[boundary..]];
            assert_eq!(
                try_keccak256_from_chunks(
                    chunks.into_iter().map(Ok::<_, core::convert::Infallible>)
                ),
                Ok(keccak256(bytes))
            );
        }
    }

    #[test]
    fn borrowed_keccak_chunks_match_one_shot_and_preserve_first_error() {
        for parts in [
            vec![],
            vec![&b""[..]],
            vec![&b"SCCP/COMMITTEE/V1"[..], &[4_u8][..], &[7_u8; 192][..]],
            vec![&b"a"[..], &b""[..], &b"bc"[..]],
        ] {
            let expected = keccak256(parts.concat());
            assert_eq!(
                try_keccak256_from_chunks(parts.into_iter().map(Ok::<_, &'static str>)),
                Ok(expected),
            );
        }
        assert_eq!(
            try_keccak256_from_chunks([[1_u8, 2], [3, 4]].into_iter().map(Ok::<_, &'static str>)),
            Ok(keccak256([1_u8, 2, 3, 4])),
            "owned fixed-size chunks use the same raw digest contract",
        );
        let inspected = std::cell::Cell::new(0);
        let chunks = [Ok(&b"prefix"[..]), Err(37_u8), Ok(&b"unread"[..])]
            .into_iter()
            .inspect(|_| inspected.set(inspected.get() + 1));
        assert_eq!(try_keccak256_from_chunks(chunks), Err(37));
        assert_eq!(inspected.get(), 2);
    }

    #[test]
    fn keccak256_returns_raw_digest_bytes() {
        assert_eq!(
            keccak256(b""),
            hex_literal::hex!("C5D2460186F7233C927E7DB2DCC703C0E500B653CA82273B7BFAD8045D85A470")
        );
    }
    #[test]
    fn hash_new_matches_blake2b_32b_with_lsb_marker() {
        let bytes = hex_literal::hex!("6920616d2064617461");
        let mut expected =
            hex_literal::hex!("BA67336EFD6A3DF3A70EEB757860763036785C182FF4CF587541A0068D09F5B2");
        expected[Hash::LENGTH - 1] |= 1;
        assert_eq!(<[u8; Hash::LENGTH]>::from(Hash::new(bytes)), expected);
    }
    #[test]
    fn hash_storage_has_no_invalid_byte_pattern() {
        assert_eq!(
            core::mem::size_of::<Hash>(),
            core::mem::size_of::<[u8; Hash::LENGTH]>()
        );
        assert_eq!(
            core::mem::align_of::<Hash>(),
            core::mem::align_of::<[u8; Hash::LENGTH]>()
        );
        // Deliberately bypass the private logical marker invariant. The raw
        // storage itself must still be a valid Rust value so archived input can
        // be inspected safely before validation, including under Miri.
        let all_zero = Hash([0; Hash::LENGTH]);
        assert_eq!(<[u8; Hash::LENGTH]>::from(all_zero), [0; Hash::LENGTH]);
    }
    #[test]
    fn hash_zeroize_clears_storage_idempotently() {
        let mut hash = Hash::new(b"confidential digest");

        hash.zeroize();
        assert_eq!(hash.0, [0; Hash::LENGTH]);

        hash.zeroize();
        assert_eq!(hash.0, [0; Hash::LENGTH]);
    }
    #[test]
    fn bounded_streaming_hash_matches_contiguous_hash_and_rejects_oversize() {
        let bytes = vec![0x5a; 3 * 64 * 1024 + 17];
        let (digest, size) = Hash::new_from_reader_bounded(bytes.as_slice(), bytes.len() as u64)
            .expect("bounded hash");
        assert_eq!(digest, Hash::new(&bytes));
        assert_eq!(size, bytes.len() as u64);
        let error = Hash::new_from_reader_bounded(bytes.as_slice(), bytes.len() as u64 - 1)
            .expect_err("input exceeds bound");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }
    #[test]
    fn hash_new_from_chunks_matches_concatenated_bytes() {
        let left: &[u8] = b"iroha:";
        let middle: &[u8] = b"chunked:";
        let right: &[u8] = b"hash";
        let mut concatenated = Vec::new();
        concatenated.extend_from_slice(left);
        concatenated.extend_from_slice(middle);
        concatenated.extend_from_slice(right);
        assert_eq!(
            Hash::new_from_chunks(&[left, middle, right]),
            Hash::new(concatenated)
        );
    }
    #[test]
    fn hash_new_from_writer_matches_chunks_and_propagates_errors() {
        let chunks: [&[u8]; 3] = [b"iroha:", b"streamed:", b"hash"];
        let streamed = Hash::new_from_writer(|writer| {
            for chunk in chunks {
                writer.write_all(chunk)?;
            }
            Ok(())
        })
        .expect("stream hash");
        assert_eq!(streamed, Hash::new_from_chunks(&chunks));
        let error = Hash::new_from_writer(|writer| {
            writer.write_all(b"partial")?;
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "producer failed",
            ))
        })
        .expect_err("producer failure must be returned");
        assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
    }
    #[test]
    fn hash_of_roundtrip() {
        use norito::codec::{Decode, Encode};
        let original = HashOf::<()>::from_untyped_unchecked(Hash::prehashed([1; Hash::LENGTH]));
        let bytes = original.encode();
        let decoded = HashOf::<()>::decode(&mut &bytes[..]).expect("failed to decode HashOf");
        assert_eq!(original, decoded);
    }
    #[test]
    fn marked_hash_constructor_preserves_bytes_and_rejects_missing_marker() {
        for last_byte in 0..=u8::MAX {
            let mut bytes = [0xa5; Hash::LENGTH];
            bytes[Hash::LENGTH - 1] = last_byte;
            let hash =
                crate::test_allocations::without_allocations(|| Hash::from_marked_bytes(bytes));
            if last_byte & 1 == 1 {
                assert_eq!(hash.unwrap().as_ref(), &bytes);
            } else {
                assert!(hash.is_none());
            }
        }
    }
    #[test]
    fn hash_of_new_matches_encoded_bytes_hash() {
        let value = vec![1_u64, 2, 3, 5, 8, 13];
        let encoded = norito::codec::Encode::encode(&value);
        let expected = HashOf::<Vec<u64>>::from_untyped_unchecked(Hash::new(encoded));
        assert_eq!(HashOf::new(&value), expected);
        assert_eq!(HashOf::try_new(&value).unwrap(), expected);
    }
    #[test]
    fn fallible_typed_hash_retains_serializer_resource_failure_after_partial_write() {
        struct Refused;
        impl norito::core::SerializePayload for Refused {
            fn serialize(
                &self,
                writer: &mut norito::core::Encoder<'_>,
            ) -> Result<(), norito::Error> {
                norito::core::SerializePayload::serialize(&7_u64, writer)?;
                Err(norito::Error::AllocationFailed { bytes: 17 })
            }
        }
        assert!(matches!(
            HashOf::try_new(&Refused),
            Err(norito::Error::AllocationFailed { bytes: 17 })
        ));
    }
    #[test]
    fn fallible_typed_hash_preserves_inherited_allocation_scope() {
        struct Charged;
        impl norito::core::SerializePayload for Charged {
            fn serialize(
                &self,
                writer: &mut norito::core::Encoder<'_>,
            ) -> Result<(), norito::Error> {
                norito::core::reserve_decode_allocation(8)?;
                norito::core::SerializePayload::serialize(&7_u64, writer)
            }
        }
        let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 8, 64);
        norito::with_decode_limits_scope(limits, || {
            assert!(HashOf::try_new(&Charged).is_ok());
            assert!(matches!(
                HashOf::try_new(&Charged),
                Err(norito::Error::TotalAllocationExceeded { .. })
            ));
        });
        assert!(HashOf::try_new(&Charged).is_ok());
    }
    #[test]
    fn hash_of_decode_rejects_invalid_lsb() {
        use norito::codec::Decode;
        for final_byte in [0x00, 0x02] {
            let mut bytes = [0xA5; Hash::LENGTH];
            bytes[Hash::LENGTH - 1] = final_byte;
            let err = HashOf::<()>::decode(&mut &bytes[..]);
            assert!(
                err.is_err(),
                "final byte {final_byte:#04x} must fail marker validation"
            );
        }
    }
    #[test]
    fn hash_of_decode_from_slice_consumes_fixed_length() {
        let original = HashOf::<()>::from_untyped_unchecked(Hash::prehashed([2; Hash::LENGTH]));
        let hash: Hash = original.into();
        let mut bytes: Vec<u8> = <[u8; Hash::LENGTH]>::from(hash).to_vec();
        bytes.extend_from_slice(&[0xAA, 0xBB]);
        let (_decoded, used) =
            <HashOf<()> as norito::core::DecodeFromSlice>::decode_from_slice(&bytes)
                .expect("decode from slice");
        assert_eq!(used, Hash::LENGTH);
    }
    #[test]
    fn from_str_rejects_even_lsb() {
        // Hex string with the final byte ending in `0`, so its least significant bit is not set.
        let invalid_hex = "BA67336EFD6A3DF3A70EEB757860763036785C182FF4CF587541A0068D09F5B0";
        assert!(Hash::from_str(invalid_hex).is_err());
    }
    #[test]
    fn hash_try_deserialize_rejects_invalid_lsb() {
        for final_byte in [0x00, 0x02] {
            let mut bytes = [0xA5; Hash::LENGTH];
            bytes[Hash::LENGTH - 1] = final_byte;
            let framed =
                norito::core::frame_bare_with_header_flags::<Hash>(&bytes, 0).expect("frame");
            let archived = norito::from_bytes::<Hash>(&framed).expect("archive");
            let err = <Hash as norito::core::DeserializePayload>::try_deserialize(archived)
                .expect_err("invalid lsb");
            assert!(matches!(
                err,
                norito::core::Error::InvalidValue {
                    context: "hash lsb"
                }
            ));
        }
    }
    #[test]
    fn hash_marker_entry_points_reject_without_allocating_and_preserve_exact_bytes() {
        for final_byte in u8::MIN..=u8::MAX {
            let mut bytes = [0xa5; Hash::LENGTH];
            bytes[Hash::LENGTH - 1] = final_byte;
            let framed = norito::core::frame_bare_with_header_flags::<Hash>(&bytes, 0).unwrap();
            let archived = norito::from_bytes::<Hash>(&framed).unwrap();
            let (slice, archived) = crate::test_allocations::without_allocations(|| {
                (
                    <Hash as norito::core::DecodeFromSlice>::decode_from_slice(&bytes),
                    <Hash as norito::core::DeserializePayload>::try_deserialize(archived),
                )
            });
            if final_byte & 1 == 1 {
                let (from_slice, used) = slice.unwrap();
                assert_eq!(used, bytes.len());
                assert_eq!(from_slice.as_ref(), &bytes);
                assert_eq!(archived.unwrap(), from_slice);
            } else {
                assert!(matches!(
                    slice,
                    Err(norito::Error::InvalidValue {
                        context: "hash lsb"
                    })
                ));
                assert!(matches!(
                    archived,
                    Err(norito::Error::InvalidValue {
                        context: "hash lsb"
                    })
                ));
            }
        }
        for length in 0..Hash::LENGTH {
            let short = [0x75; Hash::LENGTH];
            assert!(matches!(
                crate::test_allocations::without_allocations(|| {
                    <Hash as norito::core::DecodeFromSlice>::decode_from_slice(&short[..length])
                }),
                Err(norito::Error::LengthMismatch),
            ));
        }
    }

    #[test]
    fn typed_hash_marker_entry_points_preserve_static_error_and_zero_allocation() {
        for final_byte in u8::MIN..=u8::MAX {
            let mut bytes = [0x5a; Hash::LENGTH];
            bytes[Hash::LENGTH - 1] = final_byte;
            let framed =
                norito::core::frame_bare_with_header_flags::<HashOf<()>>(&bytes, 0).unwrap();
            let archived = norito::from_bytes::<HashOf<()>>(&framed).unwrap();
            let (slice, archived) = crate::test_allocations::without_allocations(|| {
                (
                    <HashOf<()> as norito::core::DecodeFromSlice>::decode_from_slice(&bytes),
                    <HashOf<()> as norito::core::DeserializePayload>::try_deserialize(archived),
                )
            });
            if final_byte & 1 == 1 {
                let (from_slice, used) = slice.unwrap();
                assert_eq!(used, bytes.len());
                assert_eq!(from_slice.as_ref(), &bytes);
                assert_eq!(archived.unwrap(), from_slice);
            } else {
                assert!(matches!(
                    slice,
                    Err(norito::Error::InvalidValue {
                        context: "hash lsb"
                    })
                ));
                assert!(matches!(
                    archived,
                    Err(norito::Error::InvalidValue {
                        context: "hash lsb"
                    })
                ));
            }
        }
    }

    #[test]
    fn hash_archived_decode_checks_every_final_byte_safely() {
        for final_byte in u8::MIN..=u8::MAX {
            let mut bytes = [0xA5; Hash::LENGTH];
            bytes[Hash::LENGTH - 1] = final_byte;
            let framed =
                norito::core::frame_bare_with_header_flags::<Hash>(&bytes, 0).expect("frame");
            let archived = norito::from_bytes::<Hash>(&framed).expect("archive");
            let result = <Hash as norito::core::DeserializePayload>::try_deserialize(archived);
            if final_byte & 1 == 1 {
                assert_eq!(
                    <[u8; Hash::LENGTH]>::from(result.expect("marked hash")),
                    bytes
                );
            } else {
                assert!(
                    result.is_err(),
                    "final byte {final_byte:#04x} must fail marker validation"
                );
            }
        }
    }
    #[test]
    fn hash_decode_from_slice_checks_every_final_byte() {
        for final_byte in u8::MIN..=u8::MAX {
            let mut bytes = [0x5A; Hash::LENGTH];
            bytes[Hash::LENGTH - 1] = final_byte;
            let result = <Hash as norito::core::DecodeFromSlice>::decode_from_slice(&bytes);
            if final_byte & 1 == 1 {
                let (hash, used) = result.expect("marked hash");
                assert_eq!(<[u8; Hash::LENGTH]>::from(hash), bytes);
                assert_eq!(used, Hash::LENGTH);
            } else {
                assert!(
                    result.is_err(),
                    "final byte {final_byte:#04x} must fail marker validation"
                );
            }
        }
    }
    #[test]
    fn hash_of_try_deserialize_rejects_invalid_final_bytes() {
        for final_byte in [0x00, 0x02] {
            let mut bytes = [0xA5; Hash::LENGTH];
            bytes[Hash::LENGTH - 1] = final_byte;
            let framed =
                norito::core::frame_bare_with_header_flags::<HashOf<()>>(&bytes, 0).expect("frame");
            let archived = norito::from_bytes::<HashOf<()>>(&framed).expect("archive");
            let err = <HashOf<()> as norito::core::DeserializePayload>::try_deserialize(archived)
                .expect_err("invalid lsb");
            assert!(matches!(
                err,
                norito::core::Error::InvalidValue {
                    context: "hash lsb"
                }
            ));
        }
    }
}
#[cfg(all(test, feature = "json"))]
mod json_tests {
    use super::*;
    use norito::{json::FastJsonWrite, literal};
    #[test]
    fn hash_json_roundtrip() {
        let hash = Hash::new(b"hash-json-roundtrip");
        let json = norito::json::to_json(&hash).expect("serialize hash");
        let body = hex::encode_upper(hash.as_ref());
        let expected = literal::format("hash", &body);
        assert_eq!(json, format!("\"{expected}\""));
        let decoded: Hash = norito::json::from_str(&json).expect("deserialize hash");
        assert_eq!(decoded, hash);
    }
    #[test]
    fn hash_json_rejects_invalid_length() {
        let err =
            norito::json::from_str::<Hash>("\"deadbeef\"").expect_err("hash must be 32 bytes");
        match err {
            norito::json::Error::Message(message) => {
                assert!(
                    message.contains("uppercase hex")
                        || message.contains("must start with `hash:`"),
                    "unexpected message: {message}"
                );
            }
            other => panic!("unexpected error: {other}"),
        }
    }
    #[test]
    fn hash_of_json_roundtrip() {
        let hash = Hash::new(b"hash-of-json");
        let hash_of = HashOf::<()>::from_untyped_unchecked(hash);
        let mut json = String::new();
        hash_of.write_json(&mut json);
        let decoded: HashOf<()> = norito::json::from_json(&json).expect("deserialize hash_of");
        assert_eq!(decoded, hash_of);
    }
    #[test]
    fn hash_literal_rejects_bad_checksum() {
        let body = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
        // Compute a canonical literal then corrupt the checksum.
        let mut literal = literal::format("hash", body);
        literal.truncate(literal.len() - 4);
        literal.push_str("0000");
        let json_literal = format!("\"{literal}\"");
        let err = norito::json::from_str::<Hash>(&json_literal).expect_err("checksum mismatch");
        match err {
            norito::json::Error::InvalidField { .. } | norito::json::Error::Message(_) => {}
            other => panic!("unexpected error: {other}"),
        }
    }
    #[test]
    fn hash_literal_rejects_lowercase_hex() {
        let body = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let literal = literal::format("hash", body);
        let json_literal = format!("\"{literal}\"");
        let err = norito::json::from_str::<Hash>(&json_literal).expect_err("lowercase rejected");
        match err {
            norito::json::Error::InvalidField { .. } | norito::json::Error::Message(_) => {}
            other => panic!("unexpected error: {other}"),
        }
    }
    #[test]
    fn hash_raw_literal_is_rejected() {
        let raw = "\"0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF\"";
        let err = norito::json::from_str::<Hash>(raw).expect_err("raw hash literal must fail");
        match err {
            norito::json::Error::InvalidField { .. } | norito::json::Error::Message(_) => {}
            other => panic!("unexpected error: {other}"),
        }
    }
}
#[cfg(test)]
mod schema_tests {
    //! Hash references retain their identity without owning their referent's schema.
    use super::*;

    #[derive(TypeId)]
    struct UnreachableReferent;

    impl IntoSchema for UnreachableReferent {
        fn type_name() -> String {
            "UnreachableReferent".to_owned()
        }

        fn update_schema_map(_: &mut iroha_schema::MetaMap) {
            panic!("a hash must not traverse its phantom referent");
        }
    }

    #[test]
    fn hash_schema_does_not_visit_phantom_referent() {
        let mut schema = HashOf::<UnreachableReferent>::schema();
        assert_eq!(
            HashOf::<UnreachableReferent>::type_name(),
            "HashOf<UnreachableReferent>"
        );
        assert!(schema.contains_key::<Hash>());
        assert!(!schema.contains_key::<UnreachableReferent>());
        let before = schema.clone();
        HashOf::<UnreachableReferent>::update_schema_map(&mut schema);
        assert_eq!(schema, before);
    }

    #[derive(IntoSchema)]
    struct HashLinkedRecord {
        previous: Option<HashOf<HashLinkedRecord>>,
    }

    #[test]
    fn self_referential_hash_schema_is_finite_from_either_root() {
        let record = HashLinkedRecord { previous: None };
        assert!(record.previous.is_none());
        let hash_schema = HashOf::<HashLinkedRecord>::schema();
        assert!(!hash_schema.contains_key::<HashLinkedRecord>());
        let record_schema = HashLinkedRecord::schema();
        assert!(record_schema.contains_key::<HashLinkedRecord>());
        assert!(record_schema.contains_key::<Option<HashOf<HashLinkedRecord>>>());
        assert!(record_schema.contains_key::<HashOf<HashLinkedRecord>>());
        assert!(record_schema.contains_key::<Hash>());
    }
}

#[cfg(test)]
mod prehashed_tests {
    use super::*;
    #[test]
    fn prehashed_sets_lsb() {
        let mut bytes = [0xff; Hash::LENGTH];
        bytes[Hash::LENGTH - 1] &= !1;
        let hash = Hash::prehashed(bytes);
        assert_eq!(hash.as_ref()[Hash::LENGTH - 1] & 1, 1);
    }
}

#[cfg(test)]
#[path = "hash_native_candidate_tests.rs"]
mod native_candidate_tests;

#[cfg(test)]
mod hash_raw_wire_tests {
    use super::*;

    #[test]
    fn hash_keeps_sole_raw_wire_and_zero_storage_charge() {
        #[repr(align(16))]
        struct Aligned([u8; 512]);
        let value = Hash::prehashed([0x25; Hash::LENGTH]);
        let raw = *value.as_ref();
        for flags in [0, norito::core::header_flags::COMPACT_LEN] {
            let _flags = norito::core::DecodeFlagsGuard::enter(flags);
            let mut encoded = Vec::new();
            norito::core::serialize_to_buffer(&value, &mut encoded).unwrap();
            assert_eq!(encoded, raw);
            let mut aligned = Aligned([0; 512]);
            aligned.0[..encoded.len()].copy_from_slice(&encoded);
            let bytes = &aligned.0[..encoded.len()];
            let zero = norito::DecodeLimits::new(0, usize::MAX, 0, 0, 8);
            let (decoded, usage) = norito::core::with_decode_limits_measured(zero, || {
                let _context = norito::core::PayloadCtxGuard::enter(bytes);
                let decoded = norito::core::decode_field_canonical::<Hash>(bytes)?;
                assert_eq!(
                    norito::core::payload_ctx(),
                    Some((bytes.as_ptr() as usize, bytes.len()))
                );
                Ok::<_, norito::Error>(decoded)
            });
            assert_eq!(decoded.unwrap(), (value, bytes.len()));
            assert_eq!(usage.total_allocated_bytes(), 0);
            assert_eq!(usage.total_elements(), 0);
            let mut alternate = Vec::new();
            norito::core::serialize_to_buffer(&raw, &mut alternate).unwrap();
            let mut extra = raw.to_vec();
            extra.push(0);
            for invalid in [&raw[..raw.len() - 1], &extra[..], &alternate[..]] {
                aligned.0[..invalid.len()].copy_from_slice(invalid);
                let bytes = &aligned.0[..invalid.len()];
                let (decoded, usage) = norito::core::with_decode_limits_measured(zero, || {
                    norito::core::decode_field_canonical::<Hash>(bytes)
                });
                assert!(matches!(decoded, Err(norito::Error::LengthMismatch)));
                assert_eq!(usage.total_allocated_bytes(), 0);
                assert_eq!(usage.total_elements(), 0);
            }
        }
    }
}
