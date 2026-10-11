//! Tests for encoded_len_exact to ensure exact sizing and buffer preallocation.
use norito::{NoritoDeserialize, NoritoSerialize, SerializePayload, to_bytes};
use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};
#[test]
fn primitive_exact_len() {
    norito::core::reset_decode_state();
    let v: u32 = 123;
    let exact = v.encoded_len_exact().expect("exact len");
    assert_eq!(exact, 4);
    let bytes = to_bytes(&v).expect("encode");
    assert_eq!(bytes.len(), norito::core::Header::SIZE + exact);
    norito::core::reset_decode_state();
}
#[test]
fn string_exact_len_matches() {
    norito::core::reset_decode_state();
    let s = String::from("hello");
    let exact = match s.encoded_len_exact() {
        Some(len) => len,
        None => return,
    };
    let expected = norito::core::len_prefix_len(s.len()) + s.len();
    assert_eq!(exact, expected);
    let bytes = to_bytes(&s).expect("encode");
    assert_eq!(bytes.len(), norito::core::Header::SIZE + expected);
    norito::core::reset_decode_state();
}
#[derive(
    Debug,
    PartialEq,
    NoritoSerialize,
    NoritoDeserialize,
    iroha_schema::IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(name = "norito.test.encoded_len_exact.S")]
struct S {
    a: u32,
    b: String,
}
#[derive(NoritoSerialize, norito::NoritoSchema)]
#[norito_schema(name = "norito.test.encoded_len_exact.NamedByteArrays")]
struct NamedByteArrays {
    tag: u8,
    digest: [u8; 32],
    suffix: [u8; 7],
}
#[derive(NoritoSerialize, norito::NoritoSchema)]
#[norito_schema(name = "norito.test.encoded_len_exact.TupleByteArrays")]
struct TupleByteArrays(u8, [u8; 32], [u8; 7]);
#[derive(Clone, Debug, PartialEq, NoritoSerialize, NoritoDeserialize, norito::NoritoSchema)]
#[norito_schema(name = "norito.test.encoded_len_exact.EnumByteArrays")]
enum EnumByteArrays {
    Tuple([u8; 32], u16),
    Named { digest: [u8; 32], suffix: [u8; 7] },
}
#[derive(Debug, PartialEq, NoritoSerialize, NoritoDeserialize, norito::NoritoSchema)]
#[norito_schema(name = "norito.test.encoded_len_exact.NestedEnumByteArrays")]
struct NestedEnumByteArrays {
    prefix: u8,
    value: EnumByteArrays,
    suffix: u8,
}
fn assert_lengths_match_payload_for_supported_layouts<T: NoritoSerialize>(value: &T) {
    use norito::core::header_flags::COMPACT_LEN;
    for flags in [0, COMPACT_LEN] {
        norito::core::reset_decode_state();
        let _guard = norito::core::DecodeFlagsGuard::enter(flags);
        let mut payload = Vec::new();
        norito::core::serialize_to_buffer(value, &mut payload)
            .expect("serialize derived byte-array payload");
        assert_eq!(
            value.encoded_len_hint(),
            Some(payload.len()),
            "derived hint differs from named/tuple byte-array bytes for flags 0x{flags:02x}"
        );
        assert_eq!(
            value.encoded_len_exact(),
            Some(payload.len()),
            "derived exact length differs from named/tuple byte-array bytes for flags 0x{flags:02x}"
        );
        let frame = norito::to_bytes(value)
            .expect("frame derived byte-array payload under every supported layout");
        let advertised_flags = frame[norito::core::Header::SIZE - 1];
        norito::core::validate_header_flags(advertised_flags)
            .expect("encoder must advertise a supported layout");
    }
    norito::core::reset_decode_state();
}
#[test]
fn derive_named_byte_array_lengths_match_every_supported_layout() {
    assert_lengths_match_payload_for_supported_layouts(&NamedByteArrays {
        tag: 9,
        digest: [0xA5; 32],
        suffix: [0x5A; 7],
    });
}
#[test]
fn derive_tuple_byte_array_lengths_match_every_supported_layout() {
    assert_lengths_match_payload_for_supported_layouts(&TupleByteArrays(9, [0xA5; 32], [0x5A; 7]));
}
#[test]
fn derive_enum_byte_array_lengths_and_nested_roundtrip_match_every_supported_layout() {
    for value in [
        EnumByteArrays::Tuple([0xA5; 32], 17),
        EnumByteArrays::Named {
            digest: [0x5A; 32],
            suffix: [0x3C; 7],
        },
    ] {
        assert_lengths_match_payload_for_supported_layouts(&value);
        let nested = NestedEnumByteArrays {
            prefix: 9,
            value,
            suffix: 11,
        };
        let bytes = to_bytes(&nested).expect("encode nested enum byte arrays");
        let decoded: NestedEnumByteArrays =
            norito::decode_from_bytes(&bytes).expect("decode nested enum byte arrays");
        assert_eq!(decoded, nested);
    }
}
#[test]
fn nested_builtin_tuple_lengths_match_every_supported_layout() {
    assert_lengths_match_payload_for_supported_layouts(&(
        7_u32,
        vec![Some(11_u32), None, Some(13_u32)],
    ));
}
#[test]
fn derive_struct_exact_len() {
    norito::core::reset_decode_state();
    let s = S {
        a: 7,
        b: "xyz".into(),
    };
    let inner_a = 4usize;
    let inner_b = norito::core::len_prefix_len(3) + 3;
    let expected = norito::core::len_prefix_len(inner_a)
        + inner_a
        + norito::core::len_prefix_len(inner_b)
        + inner_b;
    let exact = match s.encoded_len_exact() {
        Some(len) => len,
        None => return,
    };
    assert_eq!(exact, expected);
    let bytes = to_bytes(&s).expect("encode");
    assert_eq!(bytes.len(), norito::core::Header::SIZE + expected);
    norito::core::reset_decode_state();
}
#[test]
fn tuple_exact_len_matches_encoded_payload() {
    norito::core::reset_decode_state();
    let tuple = (String::from("id"), vec![1_u8, 2, 3]);
    let exact = tuple.encoded_len_exact().expect("tuple exact len");
    let bytes = to_bytes(&tuple).expect("encode");
    assert_eq!(bytes.len(), norito::core::Header::SIZE + exact);
    norito::core::reset_decode_state();
}
#[test]
fn option_exact_len() {
    norito::core::reset_decode_state();
    let some = Some(5u32);
    let some_exact = some
        .encoded_len_exact()
        .expect("Some should have exact len when its value does");
    assert_eq!(
        some_exact,
        1 + norito::core::len_prefix_len(4) + 4,
        "Some encodes as discriminator, length prefix, and payload"
    );
    let none: Option<u32> = None;
    let exact = none
        .encoded_len_exact()
        .expect("None should have exact len");
    assert_eq!(exact, 1, "None encodes as only the discriminator tag");
    norito::core::reset_decode_state();
}
#[test]
fn nonzero_exact_len_matches_primitive_width() {
    norito::core::reset_decode_state();
    assert_eq!(
        NonZeroU16::new(1)
            .expect("nonzero")
            .encoded_len_exact()
            .expect("exact len"),
        2
    );
    assert_eq!(
        NonZeroU32::new(1)
            .expect("nonzero")
            .encoded_len_exact()
            .expect("exact len"),
        4
    );
    assert_eq!(
        NonZeroU64::new(1)
            .expect("nonzero")
            .encoded_len_exact()
            .expect("exact len"),
        8
    );
    norito::core::reset_decode_state();
}
#[test]
fn vec_sequential_exact_len() {
    norito::core::reset_decode_state();
    let v: Vec<u32> = vec![1, 2, 3, 4];
    let exact = match v.encoded_len_exact() {
        Some(len) => len,
        None => return,
    };
    let expected =
        norito::core::seq_len_prefix_len(v.len()) + v.len() * (norito::core::len_prefix_len(4) + 4);
    assert_eq!(exact, expected);
    let bytes = to_bytes(&v).expect("encode");
    assert_eq!(bytes.len(), norito::core::Header::SIZE + expected);
    norito::core::reset_decode_state();
}

#[derive(
    Clone, Copy, Debug, PartialEq, NoritoSerialize, NoritoDeserialize, norito::NoritoSchema,
)]
#[norito_schema(name = "norito.test.encoded_len_exact.ExactRawEnumFields")]
#[norito(decode_from_slice)]
enum ExactRawEnumFields {
    Tuple([u8; 2]),
    Named { bytes: [u8; 2] },
}

#[test]
fn enum_raw_byte_array_fields_keep_exact_wire_and_reject_other_array_layouts_without_allocating() {
    use norito::core::{
        DecodeFlagsGuard, DecodeFromSlice, DecodeLimits, Error, header_flags, serialize_to_buffer,
        with_decode_limits, with_decode_limits_measured, write_len_header_to_vec,
    };
    for flags in [0, header_flags::COMPACT_LEN] {
        let _flags = DecodeFlagsGuard::enter(flags);
        for (tag, value) in [
            (0_u32, ExactRawEnumFields::Tuple([1, 5])),
            (1_u32, ExactRawEnumFields::Named { bytes: [1, 5] }),
        ] {
            let mut encoded = Vec::new();
            serialize_to_buffer(&value, &mut encoded).unwrap();
            let mut exact = tag.to_le_bytes().to_vec();
            write_len_header_to_vec(&mut exact, 2);
            exact.extend_from_slice(&[1, 5]);
            assert_eq!(encoded, exact);
            let zero = DecodeLimits::new(0, usize::MAX, 0, 0, 8);
            let (decoded, usage) = with_decode_limits_measured(zero, || {
                norito::core::decode_field_canonical::<ExactRawEnumFields>(&encoded)
            });
            assert_eq!(decoded.unwrap(), (value, encoded.len()));
            assert_eq!(usage.total_allocated_bytes(), 0);
            assert_eq!(usage.total_elements(), 0);
            let (slice, usage) = with_decode_limits_measured(zero, || {
                ExactRawEnumFields::decode_from_slice(&encoded)
            });
            assert_eq!(slice.unwrap(), (value, encoded.len()));
            assert_eq!(usage.total_allocated_bytes(), 0);
            assert_eq!(usage.total_elements(), 0);

            let mut alternate = Vec::new();
            serialize_to_buffer(&[1_u8, 5], &mut alternate).unwrap();
            for body in [vec![1], vec![1, 5, 7], alternate] {
                let mut invalid = tag.to_le_bytes().to_vec();
                write_len_header_to_vec(&mut invalid, body.len() as u64);
                invalid.extend_from_slice(&body);
                for result in [
                    with_decode_limits(zero, || {
                        norito::core::decode_field_canonical::<ExactRawEnumFields>(&invalid)
                    }),
                    with_decode_limits(zero, || ExactRawEnumFields::decode_from_slice(&invalid)),
                ] {
                    assert!(matches!(result, Err(Error::LengthMismatch)));
                }
            }
            let truncated = &encoded[..encoded.len() - 1];
            assert!(matches!(
                with_decode_limits(zero, || {
                    norito::core::decode_field_canonical::<ExactRawEnumFields>(truncated)
                }),
                Err(Error::LengthMismatch)
            ));
            let mut trailing = encoded.clone();
            trailing.push(0xaa);
            assert!(matches!(
                with_decode_limits(zero, || {
                    norito::core::decode_field_canonical::<ExactRawEnumFields>(&trailing)
                }),
                Err(Error::LengthMismatch)
            ));
            let mut oversized = tag.to_le_bytes().to_vec();
            write_len_header_to_vec(&mut oversized, 3);
            let narrow = DecodeLimits::new(0, 2, 0, 0, 8);
            assert!(matches!(
                with_decode_limits(narrow, || ExactRawEnumFields::decode_from_slice(&oversized)),
                Err(Error::FieldLengthExceeded {
                    length: 3,
                    limit: 2
                })
            ));
        }
    }
}
