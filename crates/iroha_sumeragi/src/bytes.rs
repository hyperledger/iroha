//! Canonical opaque byte sequences with bounded inline or admitted shared storage.

use norito::core as ncore;
use std::{
    fmt,
    hash::{Hash, Hasher},
    io,
    marker::PhantomData,
};

mod shared;
pub use shared::{ByteAdmissionError, SharedBytes, SharedDomain};

/// Storage policy for one semantic byte domain; only crate-owned policies are exposed.
pub trait ByteStorage {
    /// Minimum occupied length, before constructing storage.
    const MIN: usize = 0;
    /// Maximum occupied length, before constructing storage.
    const MAX: usize;
    /// Semantic name used for diagnostics.
    const NAME: &'static str;
    /// Fixed canonical Norito frame identity.
    const FRAME: &'static str;
    /// Borrow occupied bytes without escaping storage ownership.
    fn as_slice(&self) -> &[u8];
    /// Construct from bytes already checked against this policy.
    fn from_bytes(bytes: &[u8]) -> Self;
}

/// An opaque sequence whose policy fixes its canonical frame and allocation ownership.
#[derive(Clone, Copy)]
pub struct ByteSequence<S> {
    pub(crate) storage: S,
}
impl<S: ByteStorage> ByteSequence<S> {
    /// Occupied canonical bytes, without exposing mutable backing or unused capacity.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        self.storage.as_slice()
    }
}
impl<S: ByteStorage> fmt::Debug for ByteSequence<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple(S::NAME).field(&self.as_slice()).finish()
    }
}
impl<S: ByteStorage> PartialEq for ByteSequence<S> {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}
impl<S: ByteStorage> Eq for ByteSequence<S> {}
impl<S: ByteStorage> Hash for ByteSequence<S> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_slice().hash(state);
    }
}
impl<S: ByteStorage> ncore::SerializePayload for ByteSequence<S> {
    fn serialize(&self, encoder: &mut ncore::Encoder<'_>) -> Result<(), ncore::Error> {
        ncore::write_seq_len(encoder, self.as_slice().len() as u64)?;
        encoder.write_all(self.as_slice())?;
        Ok(())
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        Some(8 + self.as_slice().len())
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        self.encoded_len_hint()
    }
}
impl<'de, S: ByteStorage> ncore::DecodeFromSlice<'de> for ByteSequence<S> {
    fn decode_from_slice(bytes: &'de [u8]) -> Result<(Self, usize), ncore::Error> {
        let (length, prefix) = ncore::read_seq_len_slice(bytes)?;
        if !(S::MIN..=S::MAX).contains(&length) {
            // Static wire-domain bounds describe malformed bytes. They must not become
            // a retryable local decode-budget refusal at the native evidence boundary.
            return Err(if cfg!(all(test, sumeragi_mutation = "MS50")) {
                ncore::Error::FieldLengthExceeded {
                    length: length as u64,
                    limit: S::MAX as u64,
                }
            } else {
                ncore::Error::LengthMismatch
            });
        }
        let used = prefix
            .checked_add(length)
            .ok_or(ncore::Error::LengthMismatch)?;
        let data = bytes
            .get(prefix..used)
            .ok_or(ncore::Error::LengthMismatch)?;
        let value = Self {
            storage: S::from_bytes(data),
        };
        ncore::note_payload_access(bytes, used);
        Ok((value, used))
    }
}
impl<'de, S: ByteStorage> ncore::DeserializePayload<'de> for ByteSequence<S> {
    fn deserialize(archived: &'de ncore::Archived<Self>) -> Self {
        Self::try_deserialize(archived).expect("canonical bounded byte sequence")
    }
    fn try_deserialize(archived: &'de ncore::Archived<Self>) -> Result<Self, ncore::Error> {
        let bytes = ncore::payload_slice_from_ptr(std::ptr::from_ref(archived).cast())?;
        <Self as ncore::DecodeFromSlice>::decode_from_slice(bytes).map(|(value, _)| value)
    }
}
impl<S: ByteStorage> norito::NoritoSchema for ByteSequence<S> {
    fn nominal_name() -> String {
        S::FRAME.to_owned()
    }
    fn static_frame_name() -> Option<&'static str> {
        Some(S::FRAME)
    }
}
// The compiled description of the codec above, bound by the release wire-schema identity: a
// length-prefixed byte sequence identified by its domain frame and named with the length bounds
// its decoder admits.
impl<S: ByteStorage + 'static> iroha_schema::TypeId for ByteSequence<S> {
    fn id() -> String {
        S::FRAME.to_owned()
    }
}
impl<S: ByteStorage + 'static> iroha_schema::IntoSchema for ByteSequence<S> {
    fn type_name() -> String {
        format!("{}<{}..={}>", S::NAME, S::MIN, S::MAX)
    }
    fn update_schema_map(map: &mut iroha_schema::MetaMap) {
        let ty = core::any::TypeId::of::<u8>();
        if map.insert::<Self>(iroha_schema::Metadata::Vec(iroha_schema::VecMeta { ty })) {
            <u8 as iroha_schema::IntoSchema>::update_schema_map(map);
        }
    }
}

/// Semantic identity of a fixed-capacity byte sequence.
pub trait ByteDomain {
    /// Semantic name used for diagnostics.
    const NAME: &'static str;
    /// Fixed canonical Norito frame identity.
    const FRAME: &'static str;
}
/// Private inline backing. Unoccupied bytes stay zero and never enter its codec.
#[derive(Clone, Copy)]
pub struct InlineBytes<const N: usize, D> {
    bytes: [u8; N],
    len: u16,
    domain: PhantomData<D>,
}
impl<const N: usize, D: ByteDomain> ByteStorage for InlineBytes<N, D> {
    const MAX: usize = N;
    const NAME: &'static str = D::NAME;
    const FRAME: &'static str = D::FRAME;
    fn as_slice(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
    fn from_bytes(bytes: &[u8]) -> Self {
        let mut value = ByteSequence::<Self>::empty();
        value.storage.bytes[..bytes.len()].copy_from_slice(bytes);
        value.storage.len = u16::try_from(bytes.len()).expect("protocol capacity fits u16");
        value.storage
    }
}
/// Requested bytes exceed this domain's fixed protocol capacity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ByteLengthError {
    /// Requested occupied byte length.
    pub length: usize,
    /// Maximum occupied byte length of the requested domain.
    pub capacity: usize,
}
impl fmt::Display for ByteLengthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "byte length {} exceeds {}", self.length, self.capacity)
    }
}
impl std::error::Error for ByteLengthError {}
impl<const N: usize, D: ByteDomain> ByteSequence<InlineBytes<N, D>> {
    /// Empty bytes; application validation still determines whether a witness is required.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            storage: InlineBytes {
                bytes: [0; N],
                len: 0,
                domain: PhantomData,
            },
        }
    }
    /// Copy bounded canonical bytes without allocating.
    ///
    /// # Errors
    /// Rejects overflow before copying any bytes.
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, ByteLengthError> {
        if bytes.len() > N {
            return Err(ByteLengthError {
                length: bytes.len(),
                capacity: N,
            });
        }
        Ok(Self {
            storage: InlineBytes::from_bytes(bytes),
        })
    }
    /// Whether no bytes are occupied.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.storage.len == 0
    }
    /// Number of occupied bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.storage.len as usize
    }
}
impl<const N: usize, D: ByteDomain> Default for ByteSequence<InlineBytes<N, D>> {
    fn default() -> Self {
        Self::empty()
    }
}
// Failed writes preserve the original owner and bytes; there is no partial write or growth.
impl<const N: usize, D: ByteDomain> io::Write for ByteSequence<InlineBytes<N, D>> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let start = self.len();
        let end = start
            .checked_add(bytes.len())
            .filter(|end| *end <= N)
            .ok_or_else(|| io::Error::from(io::ErrorKind::WriteZero))?;
        self.storage.bytes[start..end].copy_from_slice(bytes);
        self.storage.len = u16::try_from(end).expect("protocol capacity fits u16");
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        availability::{AvailabilityFrame, MAX_DA_CHUNK_SIZE_BYTES, RowBytes},
        types::ControlWitness,
    };

    #[test]
    fn shared_codec_keeps_all_semantic_frame_domains_distinct() {
        let bytes = [1, 2, 3];
        let control = ControlWitness::try_from_slice(&bytes).unwrap();
        let availability = AvailabilityFrame::from_untrusted(bytes.to_vec()).unwrap();
        let result = RowBytes::from_untrusted(bytes.to_vec()).unwrap();
        let frames = [
            norito::encode_canonical(&control).unwrap(),
            norito::encode_canonical(&availability).unwrap(),
            norito::encode_canonical(&result).unwrap(),
        ];
        for (index, frame) in frames.iter().enumerate() {
            assert_eq!(
                norito::decode_canonical::<ControlWitness>(frame).is_ok(),
                index == 0
            );
            assert_eq!(
                norito::decode_canonical::<AvailabilityFrame>(frame).is_ok(),
                index == 1
            );
            assert_eq!(
                norito::decode_canonical::<RowBytes>(frame).is_ok(),
                index == 2
            );
        }
    }

    #[test]
    fn protocol_byte_lengths_are_terminal_codec_errors() {
        use norito::codec::{DecodeAll, Encode};
        fn invalid<T: DecodeAll + std::fmt::Debug>(length: usize) {
            let bytes = vec![7_u8; length].encode();
            let error = T::decode_all(&mut bytes.as_slice()).unwrap_err();
            assert!(
                !error.is_decode_resource_limit(),
                "protocol length {length} must be malformed, got {error:?}"
            );
            assert!(matches!(
                crate::message::CodecError::from(error),
                crate::message::CodecError::Norito(_)
            ));
        }
        invalid::<RowBytes>(0);
        invalid::<RowBytes>(MAX_DA_CHUNK_SIZE_BYTES as usize + 1);
        invalid::<ControlWitness>(crate::types::MAX_CONTROL_WITNESS_BYTES + 1);
    }

    #[test]
    fn valid_witness_local_sequence_limit_remains_retryable() {
        use norito::codec::{DecodeAll, Encode};
        let value = RowBytes::from_untrusted(vec![9; 8]).unwrap();
        let bytes = value.encode();
        let error = norito::with_decode_limits_scope(
            norito::DecodeLimits::new(7, usize::MAX, usize::MAX, usize::MAX, usize::MAX),
            || RowBytes::decode_all(&mut bytes.as_slice()),
        )
        .unwrap_err();
        assert!(error.is_decode_resource_limit(), "{error:?}");
        assert!(matches!(
            crate::message::CodecError::from(error),
            crate::message::CodecError::Resource(_)
        ));
        assert_eq!(RowBytes::decode_all(&mut bytes.as_slice()).unwrap(), value);
    }
}
