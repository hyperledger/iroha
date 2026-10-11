//! Bounded canonical record fields and direct fixed-buffer serialization shared by stores.

use iroha_allocation::ChargedBuffer;
use iroha_sumeragi::{
    message::BlockHeader,
    types::{MAX_COMMITTEE_SIZE, MAX_CONTROL_WITNESS_BYTES, MAX_PUBLIC_KEY_LEN},
};
use norito::core as ncore;
use std::{io, ops::Range};

// Twelve header fields: fixed scalar/hash/epoch fields fit 1024 bytes; every skipped key
// has at most MAX_PUBLIC_KEY_LEN occupied bytes plus 32 bytes of canonical count/field
// framing; control carries at most MAX_CONTROL_WITNESS_BYTES. This conservative metadata
// bound is independent of payload size and tested with the complete maximum-header fixture.
pub(super) const MAX_HEADER_METADATA_BYTES: usize =
    1024 + MAX_CONTROL_WITNESS_BYTES + MAX_COMMITTEE_SIZE * (MAX_PUBLIC_KEY_LEN + 32);

// Payload-only forwarding: no nested wrapper field or schema is inserted.
pub(super) struct FieldRef<'a, T>(pub(super) &'a T);
impl<T: norito::core::SerializePayload> norito::core::SerializePayload for FieldRef<'_, T> {
    fn serialize(&self, encoder: &mut norito::core::Encoder<'_>) -> Result<(), norito::Error> {
        norito::core::SerializePayload::serialize(self.0, encoder)
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        norito::core::SerializePayload::encoded_len_hint(self.0)
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        norito::core::SerializePayload::encoded_len_exact(self.0)
    }
}

// The shared protocol byte sequence uses one fixed u64 count followed by its exact bytes.
// This borrow is used by both funded writes and exact source validation during funded decoding.
pub(super) struct BytesRef<'a>(pub(super) &'a [u8]);
impl norito::core::SerializePayload for BytesRef<'_> {
    fn serialize(&self, encoder: &mut norito::core::Encoder<'_>) -> Result<(), norito::Error> {
        norito::core::write_seq_len(encoder, self.0.len() as u64)?;
        encoder.write_all(self.0)?;
        Ok(())
    }
}

pub(super) struct FixedWriter<'a>(pub(super) &'a mut ChargedBuffer<u8>);
impl io::Write for FixedWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.append(bytes)?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(super) fn field_range(bytes: &[u8], offset: &mut usize) -> Result<Range<usize>, norito::Error> {
    let rest = bytes.get(*offset..).ok_or(norito::Error::LengthMismatch)?;
    let (length, prefix) = ncore::inspect_len_from_slice(rest)?;
    let start = offset
        .checked_add(prefix)
        .ok_or(norito::Error::LengthMismatch)?;
    let end = start
        .checked_add(length)
        .ok_or(norito::Error::LengthMismatch)?;
    bytes.get(start..end).ok_or(norito::Error::LengthMismatch)?;
    *offset = end;
    Ok(start..end)
}

pub(super) fn byte_range(
    bytes: &[u8],
    field: Range<usize>,
    min: usize,
    max: usize,
) -> Result<Range<usize>, norito::Error> {
    let field_bytes = bytes
        .get(field.clone())
        .ok_or(norito::Error::LengthMismatch)?;
    let (length, prefix) = ncore::inspect_seq_len_slice(field_bytes)?;
    if !(min..=max).contains(&length) {
        return Err(norito::Error::FieldLengthExceeded {
            length: length as u64,
            limit: max as u64,
        });
    }
    let start = field
        .start
        .checked_add(prefix)
        .ok_or(norito::Error::LengthMismatch)?;
    let end = start
        .checked_add(length)
        .ok_or(norito::Error::LengthMismatch)?;
    if end != field.end {
        return Err(norito::Error::LengthMismatch);
    }
    Ok(start..end)
}

/// Decode only bounded header metadata inside an already established payload context.
/// The byte cap is enforced before any header allocation; bulk fields use separate owners.
pub(super) fn decode_header(bytes: &[u8]) -> Result<BlockHeader, norito::Error> {
    if bytes.len() > MAX_HEADER_METADATA_BYTES {
        return Err(norito::Error::FieldLengthExceeded {
            length: bytes.len() as u64,
            limit: MAX_HEADER_METADATA_BYTES as u64,
        });
    }
    let header: BlockHeader = ncore::with_decode_limits(
        norito::DecodeLimits::new(
            MAX_CONTROL_WITNESS_BYTES
                .max(MAX_COMMITTEE_SIZE)
                .max(MAX_PUBLIC_KEY_LEN),
            MAX_HEADER_METADATA_BYTES,
            MAX_HEADER_METADATA_BYTES * 2,
            MAX_HEADER_METADATA_BYTES * 8,
            ncore::MAX_VALUE_NESTING_DEPTH,
        ),
        || ncore::decode_field_canonical(bytes).map(|(header, _)| header),
    )?;
    if header.skipped_leaders.len() > MAX_COMMITTEE_SIZE
        || !header
            .skipped_leaders
            .iter()
            .all(|key| key.is_well_formed())
    {
        return Err(norito::Error::NonCanonicalEncoding);
    }
    Ok(header)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_field_ranges_and_truncated_lengths_are_errors_without_partial_cursor_updates() {
        assert!(matches!(
            byte_range(&[0; 8], 0..9, 0, 10),
            Err(norito::Error::LengthMismatch)
        ));
        assert!(matches!(
            byte_range(&[0; 8], 9..10, 0, 10),
            Err(norito::Error::LengthMismatch)
        ));
        let mut offset = 9;
        assert!(field_range(&[0; 8], &mut offset).is_err());
        assert_eq!(offset, 9);
        let _flags = ncore::DecodeFlagsGuard::enter(0);
        let mut offset = 0;
        assert!(field_range(&[0; 7], &mut offset).is_err());
        assert_eq!(offset, 0);
    }
}
