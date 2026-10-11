//! Exact declared raw instruction fields and unchanged generic array children.

use super::decode_aos_byte_array_field;
use norito::core::{
    DecodeFlagsGuard, DecodeFromSlice, DecodeLimits, Error, PayloadCtxGuard, SerializePayload,
    header_flags, serialize_to_buffer, with_decode_limits, with_decode_limits_measured,
};

#[derive(Debug, PartialEq, Eq, crate::Encode, crate::Decode)]
struct RawRecord {
    bytes: [u8; 2],
    empty: [u8; 0],
}
impl_aos_decode_from_slice!(RawRecord {
    bytes: [u8; 2],
    empty: [u8; 0],
});

#[derive(Debug, PartialEq, Eq, crate::Encode, crate::Decode)]
struct MixedRecord {
    raw: [u8; 2],
    scalar: u8,
    optional: Option<[u8; 2]>,
    vector: Vec<[u8; 2]>,
    nested: [[u8; 2]; 1],
}
impl_aos_decode_from_slice!(MixedRecord {
    raw: [u8; 2],
    scalar: u8,
    optional: Option<[u8; 2]>,
    vector: Vec<[u8; 2]>,
    nested: [[u8; 2]; 1]
});

fn bytes(value: &impl SerializePayload, flags: u8) -> Vec<u8> {
    let _flags = DecodeFlagsGuard::enter(flags);
    let mut wire = Vec::new();
    serialize_to_buffer(value, &mut wire).unwrap();
    wire
}

fn raw_frame(declared: u64, body: &[u8], flags: u8) -> Vec<u8> {
    let mut wire = Vec::new();
    norito::core::write_len_to_vec_with_flags(&mut wire, declared, flags);
    wire.extend_from_slice(body);
    wire
}

#[test]
fn direct_raw_fields_preserve_literal_wire_zero_charge_and_original_context_at_every_alignment() {
    for flags in [0, header_flags::COMPACT_LEN] {
        let value = RawRecord {
            bytes: [1, 5],
            empty: [],
        };
        let wire = bytes(&value, flags);
        let mut expected = raw_frame(2, &[1, 5], flags);
        expected.extend_from_slice(&raw_frame(0, &[], flags));
        assert_eq!(wire, expected);
        let _flags = DecodeFlagsGuard::enter(flags);
        for alignment in 0..8 {
            let mut original = vec![0xa5; alignment];
            original.extend_from_slice(&wire);
            let input = &original[alignment..];
            let limits = DecodeLimits::new(0, usize::MAX, 0, 0, 0);
            let (result, usage) = with_decode_limits_measured(limits, || {
                let _context = PayloadCtxGuard::enter(input);
                let decoded = RawRecord::decode_from_slice(input);
                assert_eq!(
                    norito::core::payload_ctx(),
                    Some((input.as_ptr() as usize, input.len()))
                );
                decoded
            });
            assert_eq!(
                result.unwrap(),
                (
                    RawRecord {
                        bytes: [1, 5],
                        empty: []
                    },
                    input.len()
                )
            );
            assert_eq!(usage.total_allocated_bytes(), 0);
            assert_eq!(usage.total_elements(), 0);
        }
    }
}

#[test]
fn raw_field_width_bounds_trailing_and_limit_precedence_remain_exact() {
    for flags in [0, header_flags::COMPACT_LEN] {
        let opposite = if flags == 0 {
            header_flags::COMPACT_LEN
        } else {
            0
        };
        let _outer = DecodeFlagsGuard::enter(opposite);
        for wire in [
            raw_frame(1, &[1], flags),
            raw_frame(3, &[1, 5, 9], flags),
            raw_frame(2, &[1], flags),
        ] {
            let mut offset = 0;
            let (result, usage) =
                with_decode_limits_measured(DecodeLimits::new(0, usize::MAX, 0, 0, 0), || {
                    decode_aos_byte_array_field::<2>(&wire, &mut offset, flags)
                });
            assert!(matches!(result, Err(Error::LengthMismatch)));
            assert_eq!(offset, 0);
            assert_eq!(usage.total_allocated_bytes(), 0);
            assert_eq!(norito::core::effective_decode_flags(), Some(opposite));
        }
        let truncated = raw_frame(2, &[], flags);
        let mut offset = 0;
        let refused = with_decode_limits(DecodeLimits::new(0, 1, 0, 0, 0), || {
            decode_aos_byte_array_field::<2>(&truncated, &mut offset, flags)
        });
        assert!(matches!(
            refused,
            Err(Error::FieldLengthExceeded {
                length: 2,
                limit: 1
            })
        ));
        assert_eq!(offset, 0);
        assert_eq!(norito::core::effective_decode_flags(), Some(opposite));

        let mut padded = bytes(
            &RawRecord {
                bytes: [1, 5],
                empty: [],
            },
            flags,
        );
        padded.push(9);
        let _flags = DecodeFlagsGuard::enter(flags);
        assert!(matches!(
            RawRecord::decode_from_slice(&padded),
            Err(Error::LengthMismatch)
        ));
    }
}

#[test]
fn optional_vector_and_nested_array_fields_keep_their_element_framed_contract() {
    for flags in [0, header_flags::COMPACT_LEN] {
        let value = MixedRecord {
            raw: [1, 5],
            scalar: 7,
            optional: Some([1, 5]),
            vector: vec![[1, 5], [2, 8]],
            nested: [[1, 5]],
        };
        let wire = bytes(&value, flags);
        let _flags = DecodeFlagsGuard::enter(flags);
        let (decoded, used) = MixedRecord::decode_from_slice(&wire).unwrap();
        assert_eq!(decoded, value);
        assert_eq!(used, wire.len());
        assert!(norito::core::decode_field_canonical::<[u8; 2]>(&[1, 5]).is_err());
        let mut collision = vec![1];
        collision.extend_from_slice(&raw_frame(2, &[1, 5], flags));
        assert!(norito::core::decode_field_canonical::<Option<[u8; 2]>>(&collision).is_err());
    }
}
