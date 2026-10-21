//! Fixed-width primitives must reject element buffers shorter than their width.

use norito::{core, decode_from_bytes, to_bytes};

/// Two-element payloads whose first fixed-width element declares 1 and 0 bytes.
const SHORT_FIRST_ELEMENT: [&[u8]; 2] =
    [&[0x01, 0xAA, 0x04, 2, 0, 0, 0], &[0x00, 0x04, 2, 0, 0, 0]];

#[test]
fn tuple_rejects_short_fixed_width_element() {
    for payload in SHORT_FIRST_ELEMENT {
        let framed = core::frame_bare_with_header_flags::<(u32, u32)>(
            payload,
            core::header_flags::COMPACT_LEN,
        )
        .expect("frame tuple");
        assert!(matches!(
            decode_from_bytes::<(u32, u32)>(&framed),
            Err(norito::Error::LengthMismatch)
        ));
    }
}

#[test]
fn array_rejects_short_fixed_width_element() {
    for payload in SHORT_FIRST_ELEMENT {
        let framed = core::frame_bare_with_header_flags::<[u64; 2]>(
            payload,
            core::header_flags::COMPACT_LEN,
        )
        .expect("frame array");
        assert!(matches!(
            decode_from_bytes::<[u64; 2]>(&framed),
            Err(norito::Error::LengthMismatch)
        ));
    }
}

#[test]
fn fixed_width_primitives_still_roundtrip() {
    let value = (7u32, -3i64, 1.5f64, 'n', true, u128::MAX);
    let bytes = to_bytes(&value).expect("encode");
    let decoded: (u32, i64, f64, char, bool, u128) = decode_from_bytes(&bytes).expect("decode");
    assert_eq!(decoded, value);

    let array = [1u16, 2, 3];
    let decoded: [u16; 3] = decode_from_bytes(&to_bytes(&array).expect("encode")).expect("decode");
    assert_eq!(decoded, array);
}
