//! Regression test for the archived `Result` decoder reading its length header
//! past the end of a short element buffer.
//!
//! A `Result<T, E>` payload is laid out as `tag(1) || length header || data`.
//! The decoder used to read the tag and the length header straight through the
//! raw archived pointer, so an element whose buffer was shorter than
//! `tag + length header` (for example a one-byte element under fixed-width
//! lengths) read up to 8 bytes past the allocation. Decoding must reject the
//! truncated buffer with a structured error instead.

use norito::{
    NoritoSerialize,
    core::{self, DecodeFlagsGuard, decode_field_canonical, header_flags},
};

fn serialize_payload<T: NoritoSerialize>(value: &T) -> Vec<u8> {
    let mut out = Vec::new();
    value.serialize(&mut out).expect("serialize");
    out
}

#[test]
fn result_truncated_length_header_is_rejected_fixed() {
    // Fixed-width lengths: the element length header is a full u64 (8 bytes).
    let _guard = DecodeFlagsGuard::enter(core::V1_DECODE_FLAGS & !header_flags::COMPACT_LEN);

    // Sanity: a well-formed buffer still decodes.
    let ok: Result<u8, u8> = Ok(7);
    let bytes = serialize_payload(&ok);
    let (decoded, used) =
        decode_field_canonical::<Result<u8, u8>>(&bytes).expect("valid result decodes");
    assert_eq!(decoded, Ok(7));
    assert_eq!(used, bytes.len());

    // Truncate to the tag byte alone. The 8-byte length header can no longer be
    // read from within the buffer; decoding must error rather than read past it.
    let err = decode_field_canonical::<Result<u8, u8>>(&bytes[..1])
        .expect_err("truncated result length header must be rejected");
    let _ = err;
}

#[test]
fn result_truncated_length_header_is_rejected_compact() {
    // Compact (varint) lengths: still must not read past a one-byte buffer.
    let _guard = DecodeFlagsGuard::enter(core::V1_DECODE_FLAGS | header_flags::COMPACT_LEN);

    let ok: Result<u8, u8> = Ok(7);
    let bytes = serialize_payload(&ok);
    let (decoded, _used) =
        decode_field_canonical::<Result<u8, u8>>(&bytes).expect("valid result decodes");
    assert_eq!(decoded, Ok(7));

    let err = decode_field_canonical::<Result<u8, u8>>(&bytes[..1])
        .expect_err("truncated result length header must be rejected");
    let _ = err;
}
