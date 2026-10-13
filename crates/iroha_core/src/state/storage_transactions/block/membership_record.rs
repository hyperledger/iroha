//! Fixed Norito records for the original located membership store.
//!
//! This codec owns one declared physical layout. Logical authentication remains
//! in the shared map kernel and canonical height reader. Locations identify an
//! immutable record within a retained generation; they are not storage leases.
//! TODO: integrate the original funded append batch, segment leases and durable
//! publication owner before using these records as a production membership store.

use std::{alloc::Layout, io::Write, num::NonZeroU64, ops::Range};

use iroha_crypto::{Hash, MerkleMapNode, MerkleMapNodeRef, MerkleMapValueRef};
use norito::core::{Encoder, FixedFrameLayout, Header, SerializePayload};

/// Exact body size, including the declared kind/version and reserved bytes.
pub(in crate::state) const PAYLOAD_BYTES: usize = 144;
/// Exact uncompressed frame size; the declared raw-byte body has alignment one.
pub(in crate::state) const FRAME_BYTES: usize = Header::SIZE + PAYLOAD_BYTES;
const RECORD_BYTES: u64 = FRAME_BYTES as u64;
const VERSION: u8 = 1;
const LEAF: u8 = 1;
const BRANCH: u8 = 2;
const HEIGHT: u8 = 3;
const SCHEMA_NAME: &str = "iroha_core::state::membership::RecordV1";

/// An aligned record offset in one explicitly retained storage generation.
/// Offsets are relative to the beginning of that owner's record area.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::state) struct MembershipLocation {
    generation: NonZeroU64,
    offset: u64,
}

impl MembershipLocation {
    /// Validate a location before retaining or serializing it.
    pub(in crate::state) fn new(generation: NonZeroU64, offset: u64) -> Result<Self, RecordError> {
        if !offset.is_multiple_of(RECORD_BYTES) || offset.checked_add(RECORD_BYTES).is_none() {
            return Err(RecordError::InvalidLocation);
        }
        Ok(Self { generation, offset })
    }

    /// Resolve only inside the exact generation and readable extent owned by
    /// the caller. The scalar arguments cannot establish that ownership.
    /// No external read or platform-sized conversion precedes these checks.
    pub(in crate::state) fn checked_range(
        self,
        generation: NonZeroU64,
        readable_bytes: u64,
    ) -> Result<Range<u64>, RecordError> {
        if self.generation != generation {
            return Err(RecordError::ForeignGeneration);
        }
        let end = self
            .offset
            .checked_add(RECORD_BYTES)
            .ok_or(RecordError::InvalidLocation)?;
        if !readable_bytes.is_multiple_of(RECORD_BYTES) || end > readable_bytes {
            return Err(RecordError::OutsideReadableExtent);
        }
        Ok(self.offset..end)
    }
}

/// One immutable tree node or its canonical nonzero height preimage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::state) enum MembershipRecord {
    /// Node descriptors carry explicit locations, excluded from logical hashes.
    Node(MerkleMapNode<MembershipLocation, MembershipLocation>),
    /// A height is authenticated against the leaf by the membership reader.
    Height(NonZeroU64),
}

/// Fixed local record failures; none establishes authenticated nonmembership.
#[derive(Debug, thiserror::Error)]
pub(in crate::state) enum RecordError {
    /// Preserve Norito framing failures and an external writer's original error.
    #[error(transparent)]
    Frame(#[from] norito::Error),
    /// The body has an unsupported version or variant tag.
    #[error("unknown membership record version or kind")]
    UnknownKind,
    /// Reserved body bytes must be zero under this exact layout.
    #[error("nonzero membership record reserved bytes")]
    ReservedBytes,
    /// A hash's mandatory low-bit marker is absent; never normalize bad bytes.
    #[error("invalid membership record hash marker")]
    InvalidHash,
    /// A branch descriptor violates its canonical local shape.
    #[error("invalid membership record branch shape")]
    InvalidBranch,
    /// Zero is not a canonical committed height.
    #[error("zero membership record height")]
    InvalidHeight,
    /// A generation is zero, or its record offset is unaligned/overflowing.
    #[error("invalid membership record location")]
    InvalidLocation,
    /// A location cannot be read through another retained generation.
    #[error("membership location belongs to another generation")]
    ForeignGeneration,
    /// The record is outside the original owner's complete readable prefix.
    #[error("membership location exceeds the readable record extent")]
    OutsideReadableExtent,
}

/// Exact raw-byte payload declaration, distinct from Norito array encoding.
#[repr(transparent)]
struct MembershipRecordPayload([u8; PAYLOAD_BYTES]);

impl norito::schema::identity::NoritoSchema for MembershipRecordPayload {
    fn nominal_name() -> String {
        SCHEMA_NAME.to_owned()
    }
}

impl SerializePayload for MembershipRecordPayload {
    fn serialize(&self, encoder: &mut Encoder<'_>) -> Result<(), norito::Error> {
        encoder.write_all(&self.0)?;
        Ok(())
    }

    fn encoded_len_hint(&self) -> Option<usize> {
        Some(PAYLOAD_BYTES)
    }

    fn encoded_len_exact(&self) -> Option<usize> {
        Some(PAYLOAD_BYTES)
    }
}

/// Reusable typed framing metadata retained by the original physical owner.
/// Creation resolves the declared schema once and requires caller funding.
/// Operations use bounded stack payloads and borrowed slices; an arbitrary
/// writer remains responsible for its own allocations and partial-write custody.
pub(in crate::state) struct MembershipRecordCodec {
    layout: FixedFrameLayout<MembershipRecordPayload>,
}

impl MembershipRecordCodec {
    /// Exact temporary schema-name allocation made during construction.
    /// Its charge may be released when `new` returns: the cached layout contains
    /// only the digest and fixed metadata, and retains no name allocation.
    pub(super) fn construction_scratch_layout() -> Layout {
        Layout::new::<[u8; SCHEMA_NAME.len()]>()
    }

    /// Construct the single schema, zero-flags, uncompressed physical layout.
    pub(in crate::state) fn new() -> Result<Self, RecordError> {
        let layout = FixedFrameLayout::new(PAYLOAD_BYTES, 0)?;
        if layout.frame_len() != FRAME_BYTES {
            return Err(norito::Error::LengthMismatch.into());
        }
        Ok(Self { layout })
    }

    /// Validate and serialize one complete frame without a growing output buffer.
    /// Semantic errors occur before the first external write; I/O errors may
    /// leave a provisional prefix, which the original append owner must retain.
    pub(in crate::state) fn write<W: Write + ?Sized>(
        &self,
        writer: &mut W,
        record: MembershipRecord,
    ) -> Result<(), RecordError> {
        let payload = encode_payload(record)?;
        self.layout.write(writer, &payload.0)?;
        Ok(())
    }

    /// Validate one exact frame and decode fixed fields from borrowed bytes.
    /// This establishes record shape, not the caller's expected logical hash,
    /// current/rollback frontier, storage generation or durable publication.
    pub(in crate::state) fn read(&self, frame: &[u8]) -> Result<MembershipRecord, RecordError> {
        let bytes = self.layout.payload(frame)?;
        let bytes: &[u8; PAYLOAD_BYTES] = bytes
            .try_into()
            .map_err(|_| norito::Error::LengthMismatch)?;
        decode_payload(bytes)
    }
}

fn encode_payload(record: MembershipRecord) -> Result<MembershipRecordPayload, RecordError> {
    let mut bytes = [0; PAYLOAD_BYTES];
    bytes[0] = VERSION;
    match record {
        MembershipRecord::Height(height) => {
            bytes[1] = HEIGHT;
            bytes[8..16].copy_from_slice(&height.get().to_le_bytes());
        }
        MembershipRecord::Node(MerkleMapNode::Leaf { key, value }) => {
            require_hash_marker(key.as_ref())?;
            require_hash_marker(value.hash.as_ref())?;
            bytes[1] = LEAF;
            bytes[8..40].copy_from_slice(key.as_ref());
            bytes[40..72].copy_from_slice(value.hash.as_ref());
            write_location(&mut bytes[72..88], value.location);
        }
        MembershipRecord::Node(MerkleMapNode::Branch {
            bit,
            prefix,
            left,
            right,
        }) => {
            validate_branch(bit, &prefix, left.hash, right.hash)?;
            bytes[1] = BRANCH;
            bytes[8..10].copy_from_slice(&bit.to_le_bytes());
            bytes[16..48].copy_from_slice(&prefix);
            bytes[48..80].copy_from_slice(left.hash.as_ref());
            write_location(&mut bytes[80..96], left.location);
            bytes[96..128].copy_from_slice(right.hash.as_ref());
            write_location(&mut bytes[128..144], right.location);
        }
    }
    Ok(MembershipRecordPayload(bytes))
}

fn decode_payload(bytes: &[u8; PAYLOAD_BYTES]) -> Result<MembershipRecord, RecordError> {
    if bytes[0] != VERSION || !matches!(bytes[1], LEAF | BRANCH | HEIGHT) {
        return Err(RecordError::UnknownKind);
    }
    require_zero(&bytes[2..8])?;
    Ok(match bytes[1] {
        HEIGHT => {
            require_zero(&bytes[16..])?;
            let height =
                NonZeroU64::new(read_u64(&bytes[8..16])?).ok_or(RecordError::InvalidHeight)?;
            MembershipRecord::Height(height)
        }
        LEAF => {
            require_zero(&bytes[88..])?;
            MembershipRecord::Node(MerkleMapNode::Leaf {
                key: read_hash(&bytes[8..40])?,
                value: MerkleMapValueRef {
                    hash: read_hash(&bytes[40..72])?,
                    location: read_location(&bytes[72..88])?,
                },
            })
        }
        BRANCH => {
            require_zero(&bytes[10..16])?;
            let bit = u16::from_le_bytes([bytes[8], bytes[9]]);
            let mut prefix = [0; Hash::LENGTH];
            prefix.copy_from_slice(&bytes[16..48]);
            let left = MerkleMapNodeRef {
                hash: read_hash(&bytes[48..80])?,
                location: read_location(&bytes[80..96])?,
            };
            let right = MerkleMapNodeRef {
                hash: read_hash(&bytes[96..128])?,
                location: read_location(&bytes[128..144])?,
            };
            validate_branch(bit, &prefix, left.hash, right.hash)?;
            MembershipRecord::Node(MerkleMapNode::Branch {
                bit,
                prefix,
                left,
                right,
            })
        }
        _ => return Err(RecordError::UnknownKind),
    })
}

fn require_zero(bytes: &[u8]) -> Result<(), RecordError> {
    if bytes.iter().any(|&byte| byte != 0) {
        return Err(RecordError::ReservedBytes);
    }
    Ok(())
}

fn read_u64(bytes: &[u8]) -> Result<u64, RecordError> {
    let bytes = bytes
        .try_into()
        .map_err(|_| norito::Error::LengthMismatch)?;
    Ok(u64::from_le_bytes(bytes))
}

fn read_hash(bytes: &[u8]) -> Result<Hash, RecordError> {
    let bytes: [u8; Hash::LENGTH] = bytes
        .try_into()
        .map_err(|_| norito::Error::LengthMismatch)?;
    require_hash_marker(&bytes)?;
    Ok(Hash::prehashed(bytes))
}

fn require_hash_marker(bytes: &[u8; Hash::LENGTH]) -> Result<(), RecordError> {
    if bytes[Hash::LENGTH - 1] & 1 == 0 {
        return Err(RecordError::InvalidHash);
    }
    Ok(())
}

fn write_location(bytes: &mut [u8], location: MembershipLocation) {
    bytes[..8].copy_from_slice(&location.generation.get().to_le_bytes());
    bytes[8..].copy_from_slice(&location.offset.to_le_bytes());
}

fn read_location(bytes: &[u8]) -> Result<MembershipLocation, RecordError> {
    let generation = NonZeroU64::new(read_u64(&bytes[..8])?).ok_or(RecordError::InvalidLocation)?;
    MembershipLocation::new(generation, read_u64(&bytes[8..])?)
}

fn validate_branch(
    bit: u16,
    prefix: &[u8; Hash::LENGTH],
    left: Hash,
    right: Hash,
) -> Result<(), RecordError> {
    require_hash_marker(left.as_ref())?;
    require_hash_marker(right.as_ref())?;
    if bit >= 256 || left == right {
        return Err(RecordError::InvalidBranch);
    }
    let byte = usize::from(bit / 8);
    let mask = u8::MAX >> (bit % 8);
    if prefix[byte] & mask != 0 || prefix[byte + 1..].iter().any(|&byte| byte != 0) {
        return Err(RecordError::InvalidBranch);
    }
    Ok(())
}

#[cfg(test)]
#[path = "membership_record_tests.rs"]
mod tests;
