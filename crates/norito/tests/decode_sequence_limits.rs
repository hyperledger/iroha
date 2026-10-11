//! Adversarial coverage for decode-scoped sequence allocation limits.
use norito::{
    DecodeLimits, Error,
    codec::{Decode, Encode},
};
use std::{
    collections::{BTreeMap, BTreeSet, BinaryHeap, HashMap, HashSet, LinkedList, VecDeque},
    io::Cursor,
    sync::{Arc, Barrier},
};
#[derive(Debug, PartialEq, Eq, Encode, Decode)]
#[cfg_attr(feature = "schema-structural", derive(iroha_schema::TypeId))]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "norito.test.decode_sequence_limits.WrappedSequence")]
enum WrappedSequence {
    Direct(Vec<u16>),
    #[expect(
        clippy::box_collection,
        reason = "regression must exercise Box decoding around a collection's terminal resource refusal"
    )]
    Boxed(Box<Vec<u16>>),
    Named {
        values: Vec<u16>,
    },
}
// Preserve the named-variant codec regression while describing its actual
// payload fields; the schema derive intentionally accepts only tuple variants.
#[cfg(feature = "schema-structural")]
#[derive(iroha_schema::IntoSchema)]
#[allow(dead_code)]
struct NamedSequenceFields {
    values: Vec<u16>,
}

#[cfg(feature = "schema-structural")]
impl iroha_schema::IntoSchema for WrappedSequence {
    fn type_name() -> String {
        "WrappedSequence".to_owned()
    }

    fn update_schema_map(map: &mut iroha_schema::MetaMap) {
        if map.contains_key::<Self>() {
            return;
        }
        map.insert::<Self>(iroha_schema::Metadata::Enum(iroha_schema::EnumMeta {
            variants: vec![
                iroha_schema::EnumVariant {
                    tag: "Direct".to_owned(),
                    discriminant: 0,
                    ty: Some(std::any::TypeId::of::<Vec<u16>>()),
                },
                iroha_schema::EnumVariant {
                    tag: "Boxed".to_owned(),
                    discriminant: 1,
                    ty: Some(std::any::TypeId::of::<Box<Vec<u16>>>()),
                },
                iroha_schema::EnumVariant {
                    tag: "Named".to_owned(),
                    discriminant: 2,
                    ty: Some(std::any::TypeId::of::<NamedSequenceFields>()),
                },
            ],
        }));
        <Vec<u16>>::update_schema_map(map);
        <Box<Vec<u16>>>::update_schema_map(map);
        NamedSequenceFields::update_schema_map(map);
    }
}

fn limits(max_sequence_elements: usize) -> DecodeLimits {
    DecodeLimits::new(
        max_sequence_elements,
        8 * 1024 * 1024,
        4 * 1024 * 1024,
        64 * 1024 * 1024,
        64,
    )
}
fn unrestricted_limits(max_sequence_elements: usize) -> DecodeLimits {
    DecodeLimits::new(
        max_sequence_elements,
        usize::MAX,
        usize::MAX,
        usize::MAX,
        128,
    )
}
fn frame_with_flags<T: norito::NoritoSerialize>(value: &T, flags: u8) -> Vec<u8> {
    let mut payload = Vec::new();
    {
        let _flags = norito::core::DecodeFlagsGuard::enter(flags);
        norito::core::serialize_to_buffer(value, &mut payload).expect("encode bare payload");
    }
    norito::core::frame_bare_with_header_flags::<T>(&payload, flags).expect("frame payload")
}
fn assert_sequence_limit(error: Error, length: u64, limit: u64) {
    assert!(
        matches!(
            &error,
            Error::SequenceLengthExceeded {
                length: actual_length,
                limit: actual_limit,
            } if *actual_length == length && *actual_limit == limit
        ),
        "unexpected error: {error:?}"
    );
}
#[test]
fn bounded_decode_accepts_the_exact_sequence_limit() {
    let value = vec![10_u32, 20, 30, 40];
    let bytes = norito::to_bytes(&value).expect("encode vector");
    let decoded: Vec<u32> = norito::decode_from_bytes_with_limits(&bytes, limits(value.len()))
        .expect("exact sequence bound must decode");
    assert_eq!(decoded, value);
}
#[test]
fn bounded_decode_rejects_one_element_over_the_limit() {
    let value = vec![10_u32, 20, 30, 40];
    let bytes = norito::to_bytes(&value).expect("encode vector");
    let error = norito::decode_from_bytes_with_limits::<Vec<u32>>(&bytes, limits(value.len() - 1))
        .expect_err("over-limit sequence must fail before allocation");
    assert_sequence_limit(error, 4, 3);
    let error =
        norito::core::decode_from_bytes_with_limits::<Vec<u32>>(&bytes, limits(value.len() - 1))
            .expect_err("bounded API must enforce the same limit");
    assert_sequence_limit(error, 4, 3);
}
#[test]
fn enum_canonical_decoders_preserve_terminal_sequence_limits() {
    for value in [
        WrappedSequence::Direct(vec![1, 2, 3, 4]),
        WrappedSequence::Boxed(Box::new(vec![1, 2, 3, 4])),
        WrappedSequence::Named {
            values: vec![1, 2, 3, 4],
        },
    ] {
        let bytes = norito::to_bytes(&value).expect("encode wrapped sequence");
        let error = norito::decode_from_bytes_with_limits::<WrappedSequence>(&bytes, limits(3))
            .expect_err("an enum decoder must preserve the terminal resource-limit error");
        assert_sequence_limit(error, 4, 3);
    }
}
#[test]
fn a_nested_scope_cannot_relax_its_outer_limit() {
    let sequence = 3_u64.to_le_bytes();
    let error = norito::with_decode_limits(limits(2), || {
        norito::with_decode_limits(limits(usize::MAX), || {
            norito::core::read_seq_len_slice(&sequence).map(|_| ())
        })
    })
    .expect_err("inner scope must inherit stricter outer limit");
    assert_sequence_limit(error, 3, 2);
}
#[test]
fn decode_error_matches_the_surviving_original_budget() {
    let sequence = norito::to_bytes(&vec![7_u64, 11, 13]).unwrap();
    let text = norito::to_bytes(&String::from("bounded field")).unwrap();
    for dimension in 0..4 {
        let mut ceilings = [usize::MAX; 4];
        ceilings[dimension] = 0;
        let outer = DecodeLimits::new(ceilings[0], ceilings[1], ceilings[2], ceilings[3], 32);
        let error = norito::with_decode_limits_scope(outer, || {
            let inner = DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, 32);
            let error = if dimension == 1 {
                norito::decode_from_bytes_with_limits::<String>(&text, inner).unwrap_err()
            } else {
                norito::decode_from_bytes_with_limits::<Vec<u64>>(&sequence, inner).unwrap_err()
            };
            assert!(matches!(
                (dimension, &error),
                (0, Error::SequenceLengthExceeded { limit: 0, .. })
                    | (1, Error::FieldLengthExceeded { limit: 0, .. })
                    | (2, Error::TotalElementsExceeded { limit: 0, .. })
                    | (3, Error::TotalAllocationExceeded { limit: 0, .. })
            ));
            assert!(norito::core::decode_error_matches_active_limits(&error));
            error
        });
        assert!(!norito::core::decode_error_matches_active_limits(&error));
        assert_eq!(
            norito::decode_from_bytes::<Vec<u64>>(&sequence).unwrap(),
            vec![7_u64, 11, 13]
        );
        assert_eq!(
            norito::decode_from_bytes::<String>(&text).unwrap(),
            "bounded field"
        );
    }
}
#[test]
fn decode_error_does_not_borrow_a_wider_scope_or_global_archive_cap() {
    let sequence = norito::to_bytes(&vec![7_u64, 11, 13]).unwrap();
    let text = norito::to_bytes(&String::from("bounded field")).unwrap();
    let wide = DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, 32);
    norito::with_decode_limits_scope(wide, || {
        for dimension in 0..4 {
            let mut ceilings = [usize::MAX; 4];
            ceilings[dimension] = 0;
            let inner = DecodeLimits::new(ceilings[0], ceilings[1], ceilings[2], ceilings[3], 32);
            let error = if dimension == 1 {
                norito::decode_from_bytes_with_limits::<String>(&text, inner).unwrap_err()
            } else {
                norito::decode_from_bytes_with_limits::<Vec<u64>>(&sequence, inner).unwrap_err()
            };
            assert!(error.decode_resource_error().is_some());
            assert!(!norito::core::decode_error_matches_active_limits(&error));
        }
        let forged =
            norito::core::frame_bare_with_header_flags::<Vec<u32>>(&u64::MAX.to_le_bytes(), 0)
                .expect("frame the forged count with an explicit layout");
        let error = norito::decode_from_bytes::<Vec<u32>>(&forged).unwrap_err();
        let canonical_limit =
            u64::try_from(norito::canonical_decode_limits(forged.len()).max_sequence_elements())
                .unwrap();
        assert!(
            matches!(&error, Error::SequenceLengthExceeded { length: u64::MAX, limit } if *limit == canonical_limit)
        );
        assert!(!norito::core::decode_error_matches_active_limits(&error));
        let mut inflated = sequence.clone();
        let archive_limit = norito::core::max_archive_len();
        let length_offset = 4 + 1 + 1 + 16 + 1;
        inflated[length_offset..length_offset + 8]
            .copy_from_slice(&(archive_limit + 1).to_le_bytes());
        let error = norito::decode_from_bytes::<Vec<u64>>(&inflated).unwrap_err();
        assert!(
            matches!(&error, Error::ArchiveLengthExceeded { length, limit } if *length == archive_limit + 1 && *limit == archive_limit)
        );
        assert!(!norito::core::decode_error_matches_active_limits(&error));
    });
}
#[test]
fn resetting_layout_state_cannot_clear_an_active_sequence_limit() {
    let sequence = 3_u64.to_le_bytes();
    let error = norito::with_decode_limits(limits(2), || {
        norito::core::reset_decode_state();
        norito::core::read_seq_len_slice(&sequence).map(|_| ())
    })
    .expect_err("layout-state reset must not erase allocation boundary");
    assert_sequence_limit(error, 3, 2);
}
#[test]
fn a_nested_scope_may_tighten_and_then_restores_the_outer_limit() {
    let sequence = 4_u64.to_le_bytes();
    norito::with_decode_limits(limits(4), || {
        let error = norito::with_decode_limits(limits(3), || {
            norito::core::read_seq_len_slice(&sequence).map(|_| ())
        })
        .expect_err("stricter nested scope must apply");
        assert_sequence_limit(error, 4, 3);
        let (length, used) = norito::core::read_seq_len_slice(&sequence)?;
        assert_eq!((length, used), (4, 8));
        Ok(())
    })
    .expect("outer scope restored after nested failure");
}
#[test]
fn bounded_scope_is_removed_after_an_error() {
    let value = vec![1_u8, 2, 3];
    let bytes = norito::to_bytes(&value).expect("encode vector");
    let error = norito::decode_from_bytes_with_limits::<Vec<u8>>(&bytes, limits(2))
        .expect_err("bounded decode must reject vector");
    assert_sequence_limit(error, 3, 2);
    let decoded: Vec<u8> = norito::decode_from_bytes(&bytes)
        .expect("default decode budget is restored after scoped failure");
    assert_eq!(decoded, value);
}
#[test]
fn default_framed_decoders_reject_forged_sequence_lengths_before_allocation() {
    let bare = u64::MAX.to_le_bytes();
    let bytes = norito::core::frame_bare_with_header_flags::<Vec<u32>>(&bare, 0)
        .expect("frame adversarial payload");
    for error in [
        norito::decode_from_bytes::<Vec<u32>>(&bytes)
            .expect_err("root default must derive a resource budget"),
        norito::core::decode_from_bytes::<Vec<u32>>(&bytes)
            .expect_err("core default must derive a resource budget"),
    ] {
        assert!(
            matches!(
                error,
                Error::SequenceLengthExceeded { .. }
                    | Error::TotalElementsExceeded { .. }
                    | Error::TotalAllocationExceeded { .. }
            ),
            "forged sequence length must fail at a decode budget: {error:?}"
        );
    }
}
#[cfg(feature = "compression")]
#[test]
fn default_decode_rejects_tiny_frame_with_huge_declared_payload() {
    const FORGED_PAYLOAD_LEN: u64 = 1024 * 1024;
    let mut bytes =
        norito::to_compressed_bytes(&vec![1_u8], Some(norito::CompressionConfig::default()))
            .expect("encode compressed fixture");
    let length_offset =
        norito::core::Header::SIZE - 2 * core::mem::size_of::<u64>() - core::mem::size_of::<u8>();
    bytes[length_offset..length_offset + core::mem::size_of::<u64>()]
        .copy_from_slice(&FORGED_PAYLOAD_LEN.to_le_bytes());
    let expected_limit =
        u64::try_from(norito::canonical_decode_limits(bytes.len()).max_total_allocated_bytes())
            .expect("default allocation limit fits u64");
    assert!(
        matches!(
            norito::decode_from_bytes::<Vec<u8>>(&bytes),
            Err(Error::TotalAllocationExceeded {
                attempted: FORGED_PAYLOAD_LEN,
                limit,
            }) if limit == expected_limit
        ),
        "the declared expansion must be charged before allocation or decompression"
    );
}
#[cfg(feature = "compression")]
#[test]
fn explicit_limits_support_trusted_high_compression_without_default_recursion() {
    let value = vec![0_u8; 256 * 1024];
    let bytes = norito::to_compressed_bytes(&value, Some(norito::CompressionConfig::default()))
        .expect("encode high-compression fixture");
    assert!(
        norito::decode_from_bytes::<Vec<u8>>(&bytes).is_err(),
        "payload-derived default must reject excessive decompression amplification"
    );
    let encoded_field_len = value.len() + core::mem::size_of::<u64>();
    let limits = DecodeLimits::new(
        value.len(),
        encoded_field_len,
        value.len(),
        value.len() * 8,
        64,
    );
    let decoded = norito::decode_from_bytes_with_limits::<Vec<u8>>(&bytes, limits)
        .expect("an explicit finite budget must support trusted compressed data");
    assert_eq!(decoded, value);
}
#[test]
fn bounded_scope_is_removed_after_unwind() {
    let unwind = std::panic::catch_unwind(|| {
        let _ = norito::with_decode_limits(limits(0), || -> Result<(), Error> {
            panic!("adversarial decoder panic");
        });
    });
    assert!(unwind.is_err());
    let sequence = 1_u64.to_le_bytes();
    let (length, used) =
        norito::core::read_seq_len_slice(&sequence).expect("limit guard restored after unwind");
    assert_eq!((length, used), (1, 8));
}
#[test]
fn tiny_archive_with_maximal_declared_count_returns_typed_error() {
    let bare = u64::MAX.to_le_bytes();
    let bytes = norito::core::frame_bare_with_header_flags::<Vec<u32>>(&bare, 0)
        .expect("frame adversarial payload");
    let error = norito::decode_from_bytes_with_limits::<Vec<u32>>(&bytes, limits(32))
        .expect_err("malicious count must be rejected before capacity reservation");
    assert_sequence_limit(error, u64::MAX, 32);
}
#[test]
fn central_limit_covers_multiple_capacity_allocating_collections() {
    let deque = VecDeque::from([1_u16, 2, 3]);
    let deque_bytes = norito::to_bytes(&deque).expect("encode deque");
    let error = norito::decode_from_bytes_with_limits::<VecDeque<u16>>(&deque_bytes, limits(2))
        .expect_err("deque sequence limit");
    assert_sequence_limit(error, 3, 2);
    let map = HashMap::from([(1_u16, 10_u16), (2, 20), (3, 30)]);
    let map_bytes = norito::to_bytes(&map).expect("encode map");
    let error = norito::decode_from_bytes_with_limits::<HashMap<u16, u16>>(&map_bytes, limits(2))
        .expect_err("map sequence limit");
    assert_sequence_limit(error, 3, 2);
}
#[test]
fn scoped_limit_covers_streaming_and_bare_sequence_decoders() {
    let value = vec![10_u32, 20, 30];
    let framed = norito::to_bytes(&value).expect("encode framed vector");
    let error = norito::decode_from_reader_with_limits::<_, Vec<u32>>(
        std::io::Cursor::new(&framed),
        limits(2),
    )
    .expect_err("bounded reader API must honor sequence limit");
    assert_sequence_limit(error, 3, 2);
    let error = norito::with_decode_limits(limits(2), || {
        norito::stream_vec_collect_from_reader::<_, u32>(std::io::Cursor::new(&framed))
    })
    .expect_err("streaming vector must honor scoped limit");
    assert_sequence_limit(error, 3, 2);
    let bare = norito::codec::encode_adaptive(&value);
    let error = norito::with_decode_limits(limits(2), || {
        norito::codec::decode_adaptive::<Vec<u32>>(&bare)
    })
    .expect_err("bare vector must honor scoped limit");
    assert_sequence_limit(error, 3, 2);
}
#[test]
fn generic_scoped_limit_preserves_wrapped_error_type() {
    #[derive(Debug)]
    struct WrappedError(Error);
    let value = vec![10_u32, 20, 30];
    let framed = norito::to_bytes(&value).expect("encode framed vector");
    let error = norito::with_decode_limits_scope(limits(2), || {
        norito::stream_vec_collect_from_reader::<_, u32>(Cursor::new(&framed)).map_err(WrappedError)
    })
    .expect_err("generic scope must enforce limits through a wrapped error");
    assert_sequence_limit(error.0, 3, 2);
}
#[test]
fn scoped_limit_covers_adaptive_row_decoders() {
    let rows = [(1_u64, 10_u32, true), (2, 20, false), (3, 30, true)];
    let aos = norito::aos::encode_rows_u64_u32_bool(&rows);
    let error =
        norito::with_decode_limits(limits(2), || norito::aos::decode_rows_u64_u32_bool(&aos))
            .expect_err("AoS decoder must honor scoped limit");
    assert_sequence_limit(error, 3, 2);
    let string_rows = [(1_u64, "one", true), (2, "two", false), (3, "three", true)];
    let ncb = norito::columnar::encode_ncb_u64_str_bool(&string_rows);
    let error = norito::with_decode_limits(limits(2), || {
        norito::columnar::view_ncb_u64_str_bool(&ncb).map(|_| ())
    })
    .expect_err("columnar decoder must honor scoped limit");
    assert_sequence_limit(error, 3, 2);
}
#[test]
fn zero_limit_accepts_only_empty_sequences() {
    let empty = norito::to_bytes(&Vec::<u64>::new()).expect("encode empty vector");
    let decoded: Vec<u64> = norito::decode_from_bytes_with_limits(&empty, limits(0))
        .expect("zero bound accepts empty sequence");
    assert!(decoded.is_empty());
    let non_empty = norito::to_bytes(&vec![1_u64]).expect("encode vector");
    let error = norito::decode_from_bytes_with_limits::<Vec<u64>>(&non_empty, limits(0))
        .expect_err("zero bound rejects non-empty sequence");
    assert_sequence_limit(error, 1, 0);
}
#[test]
fn field_and_cumulative_allocation_budgets_are_typed() {
    let four = 4_u64.to_le_bytes();
    let five = 5_u64.to_le_bytes();
    let field_error = norito::with_decode_limits(DecodeLimits::new(16, 4, 64, 64, 8), || {
        norito::core::read_len_from_slice_with_flags(&five, 0).map(|_| ())
    })
    .expect_err("field limit must reject the declared body");
    assert!(matches!(
        field_error,
        Error::FieldLengthExceeded {
            length: 5,
            limit: 4
        }
    ));
    let allocation_error = norito::with_decode_limits(DecodeLimits::new(16, 16, 64, 7, 8), || {
        norito::core::read_len_from_slice_with_flags(&four, 0)?;
        norito::core::read_len_from_slice_with_flags(&four, 0).map(|_| ())
    })
    .expect_err("cumulative field bytes must share one budget");
    assert!(matches!(
        allocation_error,
        Error::TotalAllocationExceeded {
            attempted: 8,
            limit: 7
        }
    ));
}
#[test]
fn cumulative_element_budget_covers_nested_sequences() {
    let value = vec![vec![1_u8, 2], vec![3, 4]];
    let bytes = norito::to_bytes(&value).expect("encode nested vectors");
    let error = norito::decode_from_bytes_with_limits::<Vec<Vec<u8>>>(
        &bytes,
        DecodeLimits::new(8, 1024, 5, 64 * 1024, 8),
    )
    .expect_err("outer plus nested sequence counts must share a total");
    assert!(matches!(
        error,
        Error::TotalElementsExceeded {
            attempted: 6,
            limit: 5
        }
    ));
}
#[test]
fn nesting_depth_budget_rejects_deep_values() {
    let value = vec![vec![vec![1_u8]]];
    let bytes = norito::to_bytes(&value).expect("encode nested vectors");
    let error = norito::decode_from_bytes_with_limits::<Vec<Vec<Vec<u8>>>>(
        &bytes,
        DecodeLimits::new(8, 1024, 64, 64 * 1024, 1),
    )
    .expect_err("second nested field decode must exceed depth one");
    assert!(matches!(
        error,
        Error::NestingDepthExceeded {
            depth: 2,
            limit: 1,
            context: "decode budget",
        }
    ));
}
#[test]
fn malformed_result_array_and_tuple_lengths_do_not_allocate_first() {
    const FORGED_LENGTH: u64 = 1 << 30;
    let mut result_payload = vec![0_u8];
    result_payload.extend_from_slice(&FORGED_LENGTH.to_le_bytes());
    let result_bytes =
        norito::core::frame_bare_with_header_flags::<Result<u8, u8>>(&result_payload, 0)
            .expect("frame result");
    let result_error = norito::decode_from_bytes_with_limits::<Result<u8, u8>>(
        &result_bytes,
        unrestricted_limits(8),
    )
    .expect_err("truncated Result body must fail before allocation");
    assert!(matches!(result_error, Error::LengthMismatch));
    let tuple_payload = FORGED_LENGTH.to_le_bytes();
    let tuple_bytes = norito::core::frame_bare_with_header_flags::<(u8, u8)>(&tuple_payload, 0)
        .expect("frame tuple");
    let tuple_error =
        norito::decode_from_bytes_with_limits::<(u8, u8)>(&tuple_bytes, unrestricted_limits(8))
            .expect_err("truncated tuple field must fail before allocation");
    assert!(matches!(tuple_error, Error::LengthMismatch));
    let array_payload = FORGED_LENGTH.to_le_bytes();
    let array_bytes = norito::core::frame_bare_with_header_flags::<[u16; 1]>(&array_payload, 0)
        .expect("frame array");
    let array_error =
        norito::decode_from_bytes_with_limits::<[u16; 1]>(&array_bytes, unrestricted_limits(8))
            .expect_err("truncated array field must fail before allocation");
    assert!(matches!(array_error, Error::LengthMismatch));
}
#[test]
fn malformed_stream_element_length_is_checked_before_scratch_growth() {
    const FORGED_LENGTH: u64 = 1 << 30;
    let mut payload = 1_u64.to_le_bytes().to_vec();
    payload.extend_from_slice(&FORGED_LENGTH.to_le_bytes());
    let bytes =
        norito::core::frame_bare_with_header_flags::<Vec<u16>>(&payload, 0).expect("frame stream");
    let collector_error = norito::with_decode_limits(unrestricted_limits(8), || {
        norito::stream_vec_collect_from_reader::<_, u16>(Cursor::new(bytes.clone()))
    })
    .expect_err("collector must reject a body larger than remaining payload");
    assert!(matches!(collector_error, Error::LengthMismatch));
    let mut iterator = norito::stream_seq_iter_with_limits::<_, u16>(
        Cursor::new(bytes.clone()),
        unrestricted_limits(8),
    )
    .expect("iterator header and count are valid");
    let iterator_error = iterator
        .next()
        .expect("declared item")
        .expect_err("iterator must reject body before scratch allocation");
    assert!(matches!(iterator_error, Error::LengthMismatch));
    let iterator =
        norito::stream_seq_iter_with_limits::<_, u16>(Cursor::new(bytes), unrestricted_limits(8))
            .expect("finish iterator header and count are valid");
    let finish_error = iterator
        .finish()
        .expect_err("finish must reject body before scratch allocation");
    assert!(matches!(finish_error, Error::LengthMismatch));
}
#[test]
fn truncated_counts_fail_before_count_driven_reservations() {
    let vector_payload = 32_u64.to_le_bytes();
    let vector_bytes = norito::core::frame_bare_with_header_flags::<Vec<u16>>(&vector_payload, 0)
        .expect("frame truncated vector");
    let vector_error = norito::core::decode_from_bytes_with_limits::<Vec<u16>>(
        &vector_bytes,
        DecodeLimits::new(32, 1024, 32, 32, 8),
    )
    .expect_err("missing element headers must win before planning reservations");
    assert!(matches!(vector_error, Error::LengthMismatch));
    let stream_error = norito::with_decode_limits(DecodeLimits::new(32, 1024, 32, 32, 8), || {
        norito::stream_vec_collect_from_reader::<_, u16>(Cursor::new(vector_bytes))
    })
    .expect_err("stream collector must validate minimum headers before output reservation");
    assert!(matches!(stream_error, Error::LengthMismatch));
    let map_payload = 2_u64.to_le_bytes();
    let map_bytes = norito::core::frame_bare_with_header_flags::<HashMap<u8, u8>>(&map_payload, 0)
        .expect("frame truncated map");
    let map_error = norito::core::decode_from_bytes_with_limits::<HashMap<u8, u8>>(
        &map_bytes,
        DecodeLimits::new(2, 1024, 2, 2, 8),
    )
    .expect_err("missing map headers must win before capacity reservation");
    assert!(matches!(map_error, Error::LengthMismatch));
}
#[test]
fn bounded_lazy_map_finish_reapplies_field_limits() {
    let mut payload = 1_u64.to_le_bytes().to_vec();
    payload.extend_from_slice(&5_u64.to_le_bytes());
    payload.extend_from_slice(&[0_u8; 8]);
    let bytes = norito::core::frame_bare_with_header_flags::<HashMap<u8, u8>>(&payload, 0)
        .expect("frame malformed map");
    let iterator = norito::StreamMapIter::<u8, u8>::new_hash_with_limits(
        Cursor::new(bytes),
        DecodeLimits::new(8, 4, 64, 64 * 1024, 8),
    )
    .expect("map count and minimum headers are valid");
    let error = iterator
        .finish()
        .expect_err("finish must reapply the stored field budget");
    assert!(matches!(
        error,
        Error::FieldLengthExceeded {
            length: 5,
            limit: 4
        }
    ));
}
#[test]
fn historical_enum_and_direct_optional_columns_honor_limits() {
    use norito::columnar::EnumBorrow;
    let rows = [
        (1_u64, EnumBorrow::Code(10), true),
        (2, EnumBorrow::Code(20), false),
        (3, EnumBorrow::Code(30), true),
    ];
    let aos = norito::aos::encode_rows_u64_enum_bool(&rows);
    let direct_error = norito::with_decode_limits(limits(2), || {
        norito::aos::decode_rows_u64_enum_bool(&aos).map(|_| ())
    })
    .expect_err("historical enum AoS count must be bounded");
    assert_sequence_limit(direct_error, 3, 2);
    let mut adaptive = vec![norito::columnar::ADAPTIVE_ENUM_TAG_AOS];
    adaptive.extend_from_slice(&aos);
    let adaptive_error = norito::with_decode_limits(limits(2), || {
        norito::columnar::decode_rows_u64_enum_bool_adaptive(&adaptive).map(|_| ())
    })
    .expect_err("adaptive enum AoS route must retain the bound");
    assert_sequence_limit(adaptive_error, 3, 2);
    let strings = [Some("one"), None, Some("three")];
    let (string_column, _) = norito::columnar::encode_opt_str_column(&strings);
    let string_error = norito::with_decode_limits(limits(2), || {
        norito::columnar::view_opt_str_column(&string_column, strings.len()).map(|_| ())
    })
    .expect_err("direct optional string view must enforce n_rows");
    assert_sequence_limit(string_error, 3, 2);
    let numbers = [Some(1_u32), None, Some(3)];
    let (number_column, _) = norito::columnar::encode_opt_u32_column(&numbers);
    let number_error = norito::with_decode_limits(limits(2), || {
        norito::columnar::view_opt_u32_column(&number_column, numbers.len()).map(|_| ())
    })
    .expect_err("direct optional integer view must enforce n_rows");
    assert_sequence_limit(number_error, 3, 2);
    let name_rows = [(1_u64, EnumBorrow::Name("abcde"), true)];
    let name_aos = norito::aos::encode_rows_u64_enum_bool(&name_rows);
    let name_error = norito::with_decode_limits(DecodeLimits::new(8, 4, 64, 1024, 8), || {
        norito::aos::decode_rows_u64_enum_bool(&name_aos).map(|_| ())
    })
    .expect_err("historical enum names must honor the field-byte cap");
    assert!(matches!(
        name_error,
        Error::FieldLengthExceeded {
            length: 5,
            limit: 4
        }
    ));
    let ncb = norito::columnar::encode_ncb_u64_str_bool(&[(1_u64, "abcde", true)]);
    let blob_error = norito::with_decode_limits(DecodeLimits::new(8, 4, 64, 1024, 8), || {
        norito::columnar::view_ncb_u64_str_bool(&ncb).map(|_| ())
    })
    .expect_err("columnar blob offsets must honor the field-byte cap");
    assert!(matches!(
        blob_error,
        Error::FieldLengthExceeded {
            length: 5,
            limit: 4
        }
    ));
}
#[test]
fn bounded_lazy_sequence_retains_limits_after_constructor_returns() {
    let value = vec![vec![1_u8, 2, 3]];
    let bytes = norito::to_bytes(&value).expect("encode nested vector");
    let mut iterator =
        norito::stream_seq_iter_with_limits::<_, Vec<u8>>(Cursor::new(bytes), limits(2))
            .expect("outer sequence is within limit");
    let error = iterator
        .next()
        .expect("outer item")
        .expect_err("nested vector must retain iterator limit");
    assert_sequence_limit(error, 3, 2);
}
#[test]
fn bounded_lazy_map_retains_limits_for_nested_values() {
    let map = HashMap::from([(1_u8, vec![1_u8, 2, 3])]);
    for flags in [0, norito::core::header_flags::COMPACT_LEN] {
        let frame = frame_with_flags(&map, flags);
        let mut iterator = norito::StreamMapIter::<u8, Vec<u8>>::new_hash_with_limits(
            Cursor::new(frame),
            limits(2),
        )
        .expect("outer map is within limit");
        let error = iterator
            .next()
            .expect("map entry")
            .expect_err("nested value must retain limit");
        assert_sequence_limit(error, 3, 2);
    }
}
#[test]
fn compressed_and_additional_collection_decoders_are_bounded() {
    let values = vec![1_u16, 2, 3];
    let compressed =
        norito::to_compressed_bytes(&values, Some(norito::CompressionConfig::default()))
            .expect("encode compressed vector");
    let error = norito::decode_from_bytes_with_limits::<Vec<u16>>(&compressed, limits(2))
        .expect_err("compressed decode must retain sequence budget");
    assert_sequence_limit(error, 3, 2);
    let btree = BTreeMap::from([(1_u8, 1_u8), (2, 2), (3, 3)]);
    let heap = BinaryHeap::from([1_u8, 2, 3]);
    let hash_set = HashSet::from([1_u8, 2, 3]);
    let btree_set = BTreeSet::from([1_u8, 2, 3]);
    let linked: LinkedList<u8> = [1_u8, 2, 3].into_iter().collect();
    let btree_error = norito::decode_from_bytes_with_limits::<BTreeMap<u8, u8>>(
        &norito::to_bytes(&btree).expect("encode BTreeMap"),
        limits(2),
    )
    .expect_err("BTreeMap limit");
    assert_sequence_limit(btree_error, 3, 2);
    let heap_error = norito::decode_from_bytes_with_limits::<BinaryHeap<u8>>(
        &norito::to_bytes(&heap).expect("encode heap"),
        limits(2),
    )
    .expect_err("heap limit");
    assert_sequence_limit(heap_error, 3, 2);
    let hash_set_error = norito::decode_from_bytes_with_limits::<HashSet<u8>>(
        &norito::to_bytes(&hash_set).expect("encode HashSet"),
        limits(2),
    )
    .expect_err("HashSet limit");
    assert_sequence_limit(hash_set_error, 3, 2);
    let btree_set_error = norito::decode_from_bytes_with_limits::<BTreeSet<u8>>(
        &norito::to_bytes(&btree_set).expect("encode BTreeSet"),
        limits(2),
    )
    .expect_err("BTreeSet limit");
    assert_sequence_limit(btree_set_error, 3, 2);
    let linked_error = norito::decode_from_bytes_with_limits::<LinkedList<u8>>(
        &norito::to_bytes(&linked).expect("encode LinkedList"),
        limits(2),
    )
    .expect_err("LinkedList limit");
    assert_sequence_limit(linked_error, 3, 2);
}
#[test]
fn concurrent_scopes_keep_independent_budgets() {
    let value = vec![1_u8, 2, 3];
    let bytes = Arc::new(norito::to_bytes(&value).expect("encode vector"));
    let barrier = Arc::new(Barrier::new(2));
    let strict_bytes = Arc::clone(&bytes);
    let strict_barrier = Arc::clone(&barrier);
    let strict = std::thread::spawn(move || {
        strict_barrier.wait();
        norito::decode_from_bytes_with_limits::<Vec<u8>>(strict_bytes.as_slice(), limits(2))
    });
    let permissive_bytes = Arc::clone(&bytes);
    let permissive_barrier = Arc::clone(&barrier);
    let permissive = std::thread::spawn(move || {
        permissive_barrier.wait();
        norito::decode_from_bytes_with_limits::<Vec<u8>>(permissive_bytes.as_slice(), limits(3))
    });
    let strict_error = strict
        .join()
        .expect("strict worker")
        .expect_err("strict worker must reject");
    assert_sequence_limit(strict_error, 3, 2);
    assert_eq!(
        permissive
            .join()
            .expect("permissive worker")
            .expect("permissive worker must decode"),
        value
    );
}
