//! Focused tests for the Norito core codec.
use super::*;
use crate::{
    DeserializePayload, NoritoDeserialize, NoritoSerialize, SerializePayload, codec,
    codec::{encode_adaptive, encode_with_header_flags},
};
use crc64fast::Digest;
use std::sync::atomic::{AtomicUsize, Ordering};

#[test]
fn active_decode_depth_requires_exact_narrower_surviving_caller() {
    let bytes = crate::to_bytes(&vec![vec![7_u64]]).unwrap();
    let narrow = DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, 0);
    let wide = DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, 64);
    with_decode_limits_scope(narrow, || {
        let error = crate::decode_from_bytes::<Vec<Vec<u64>>>(&bytes).unwrap_err();
        assert!(decode_error_matches_active_limits(&error));
        assert!(matches!(
            error,
            Error::NestingDepthExceeded {
                depth: 1,
                limit: 0,
                context: "decode budget"
            }
        ));
    });
    with_decode_limits_scope(wide, || {
        let error =
            with_decode_limits_scope(narrow, || crate::decode_from_bytes::<Vec<Vec<u64>>>(&bytes))
                .unwrap_err();
        assert!(!decode_error_matches_active_limits(&error));
        // Exercise the real private codec guard at its canonical ceiling, without fabricating an error.
        let error = with_decode_limits_scope(crate::canonical_decode_limits(bytes.len()), || {
            let mut guards = Vec::new();
            for _ in 0..MAX_VALUE_NESTING_DEPTH {
                guards.push(DecodeDepthGuard::enter()?);
            }
            DecodeDepthGuard::enter().map(|_guard| ())
        })
        .unwrap_err();
        assert!(matches!(error, Error::NestingDepthExceeded {
            depth, limit: MAX_VALUE_NESTING_DEPTH, context: "decode budget"
        } if depth == MAX_VALUE_NESTING_DEPTH + 1));
        assert!(!decode_error_matches_active_limits(&error));
    });
    assert_eq!(
        crate::decode_from_bytes::<Vec<Vec<u64>>>(&bytes).unwrap(),
        vec![vec![7_u64]]
    );
}

#[test]
fn decode_resource_error_preserves_every_variant_and_field() {
    let errors = [
        Error::ArchiveLengthExceeded {
            length: 101,
            limit: 100,
        },
        Error::SequenceLengthExceeded {
            length: 51,
            limit: 50,
        },
        Error::FieldLengthExceeded {
            length: 31,
            limit: 30,
        },
        Error::TotalElementsExceeded {
            attempted: 21,
            limit: 20,
        },
        Error::TotalAllocationExceeded {
            attempted: 11,
            limit: 10,
        },
        Error::AllocationFailed { bytes: 2048 },
        Error::NestingDepthExceeded {
            depth: 5,
            limit: 4,
            context: "resource fixture",
        },
    ];
    for error in errors {
        let resource = error.decode_resource_error().expect("typed refusal");
        let recovered = Error::from(resource);
        assert!(error.is_decode_resource_limit());
        assert_eq!(format!("{recovered:?}"), format!("{error:?}"));
        assert_eq!(resource.to_string(), error.to_string());
        assert_eq!(recovered.decode_resource_error(), Some(resource));
    }
    for error in [
        Error::NonCanonicalEncoding,
        Error::ChecksumMismatch,
        Error::Message("failed to allocate 2048 bytes while decoding".into()),
        Error::Io(std::io::ErrorKind::OutOfMemory.into()),
    ] {
        assert_eq!(error.decode_resource_error(), None);
        assert!(!error.is_decode_resource_limit());
    }
}

#[test]
fn encoder_sink_paths_produce_identical_bytes() {
    let value = 0xA1B2_C3D4_E5F6_0718_u64;
    let mut buffered = Vec::new();
    serialize_to_buffer(&value, &mut buffered).expect("serialize through buffer sink");
    let mut erased = Vec::new();
    serialize_to_writer(&value, &mut erased).expect("serialize through erased writer sink");
    let mut byte_sink = ByteSink::with_headroom(8, 0);
    let mut encoder = Encoder::for_byte_sink(&mut byte_sink);
    value
        .serialize(&mut encoder)
        .expect("serialize through checksum sink");
    let checksummed = byte_sink.into_inner();
    assert_eq!(buffered, value.to_le_bytes());
    assert_eq!(erased, buffered);
    assert_eq!(checksummed, buffered);
}
#[test]
fn encoder_erased_sink_propagates_write_errors() {
    struct FailingWriter;
    impl Write for FailingWriter {
        fn write(&mut self, _bytes: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("intentional encoder failure"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut writer = FailingWriter;
    let error = serialize_to_writer(&7_u8, &mut writer)
        .expect_err("the writer error must cross the encoder boundary");
    assert!(matches!(error, Error::Io(_)));
}
#[test]
fn fixed_array_decode_builds_in_place_without_heap_staging() {
    reset_decode_state();
    let value = [0x1234_u16, 0x5678_u16];
    let mut bytes = Vec::new();
    serialize_to_buffer(&value, &mut bytes).expect("serialize fixed array payload");
    let limits = DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX);
    let (decoded, usage) = with_decode_limits_measured(limits, || {
        <[u16; 2] as DecodeFromSlice>::decode_from_slice(&bytes)
    });
    assert_eq!(decoded.expect("fixed array decode").0, value);
    assert_eq!(usage.total_allocated_bytes(), 0);
    reset_decode_state();
}
#[test]
fn fixed_byte_array_decode_reports_prefix_used() {
    reset_decode_state();
    let value = [3_u8, 5, 8, 13];
    let mut encoded = Vec::new();
    serialize_to_buffer(&value, &mut encoded).expect("encode fixed byte array");
    let mut with_tail = encoded.clone();
    with_tail.extend_from_slice(&[0xAA, 0xBB]);
    let (decoded, used) = <[u8; 4] as DecodeFromSlice>::decode_from_slice(&with_tail)
        .expect("decode fixed byte-array prefix");
    assert_eq!(decoded, value);
    assert_eq!(used, encoded.len());
    assert!(matches!(
        decode_field_canonical::<[u8; 4]>(&with_tail),
        Err(Error::LengthMismatch)
    ));
    let decode_raw = |bytes: &[u8]| {
        let _context = PayloadCtxGuard::enter(bytes);
        let mut used = 0;
        let decoded = decode_context_byte_array::<4>(bytes.as_ptr(), &mut used)?;
        finish_context_fields(bytes.as_ptr(), used)?;
        Ok::<_, Error>((decoded, used))
    };
    assert_eq!(
        decode_raw(&value).expect("decode explicit raw fixed byte-array field"),
        (value, value.len())
    );
    assert!(matches!(
        decode_raw(&value[..3]),
        Err(Error::LengthMismatch)
    ));
    reset_decode_state();
}
#[test]
fn fixed_array_initializer_drops_completed_elements_after_an_error() {
    static DROPS: AtomicUsize = AtomicUsize::new(0);
    #[derive(Debug)]
    struct DropProbe;
    impl Drop for DropProbe {
        fn drop(&mut self) {
            DROPS.fetch_add(1, Ordering::Relaxed);
        }
    }
    DROPS.store(0, Ordering::Relaxed);
    let mut calls = 0;
    let error = try_decode_array::<DropProbe, 4>(|| {
        calls += 1;
        if calls == 3 {
            Err(Error::LengthMismatch)
        } else {
            Ok(DropProbe)
        }
    })
    .expect_err("third element must fail");
    assert!(matches!(error, Error::LengthMismatch));
    assert_eq!(DROPS.load(Ordering::Relaxed), 2);
}
#[test]
fn owned_pointer_decoders_charge_their_wrapper_allocations() {
    fn limits_below(bytes: usize) -> DecodeLimits {
        DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, bytes - 1, usize::MAX)
    }
    reset_decode_state();
    // Use an alignment-one payload so this regression isolates the owned
    // wrapper allocation rather than also charging a field realignment copy.
    let mut bytes = Vec::new();
    serialize_to_buffer(&Box::new(7_u8), &mut bytes).expect("serialize Box");
    let box_bytes = owned_box_allocation_bytes::<u8>();
    let error = with_decode_limits(limits_below(box_bytes), || {
        <Box<u8> as DecodeFromSlice>::decode_from_slice(&bytes).map(|_| ())
    })
    .expect_err("Box allocation must be charged");
    assert!(matches!(
        error,
        Error::TotalAllocationExceeded { attempted, limit }
            if attempted == box_bytes as u64 && limit == (box_bytes - 1) as u64
    ));
    bytes.clear();
    serialize_to_buffer(&Rc::new(7_u8), &mut bytes).expect("serialize Rc");
    let rc_bytes = owned_rc_allocation_bytes::<u8>().expect("Rc layout must fit");
    let error = with_decode_limits(limits_below(rc_bytes), || {
        <Rc<u8> as DecodeFromSlice>::decode_from_slice(&bytes).map(|_| ())
    })
    .expect_err("Rc allocation must be charged");
    assert!(
        matches!(
            error,
            Error::TotalAllocationExceeded { attempted, limit }
                if attempted == rc_bytes as u64 && limit == (rc_bytes - 1) as u64
        ),
        "unexpected Rc allocation error: {error:?}; wrapper bytes: {rc_bytes}"
    );
    bytes.clear();
    serialize_to_buffer(&Arc::new(7_u8), &mut bytes).expect("serialize Arc");
    let arc_bytes = owned_arc_allocation_bytes::<u8>().expect("Arc layout must fit");
    let error = with_decode_limits(limits_below(arc_bytes), || {
        <Arc<u8> as DecodeFromSlice>::decode_from_slice(&bytes).map(|_| ())
    })
    .expect_err("Arc allocation must be charged");
    assert!(matches!(
        error,
        Error::TotalAllocationExceeded { attempted, limit }
            if attempted == arc_bytes as u64 && limit == (arc_bytes - 1) as u64
    ));
    reset_decode_state();
}
#[test]
fn owned_value_decode_depth_guard_is_bounded_and_restores() {
    let guards = (0..MAX_VALUE_NESTING_DEPTH)
        .map(|_| OwnedValueDecodeDepthGuard::enter().expect("depth within codec limit"))
        .collect::<Vec<_>>();
    assert!(matches!(
        OwnedValueDecodeDepthGuard::enter(),
        Err(Error::NestingDepthExceeded {
            depth,
            limit: MAX_VALUE_NESTING_DEPTH,
            context: "owned Norito value",
        }) if depth == MAX_VALUE_NESTING_DEPTH + 1
    ));
    drop(guards);
    OwnedValueDecodeDepthGuard::enter().expect("failed guard must restore decode depth");
}
#[test]
fn crc64_matches_digest() {
    let data = b"123456789";
    let mut digest = Digest::new();
    digest.write(data);
    assert_eq!(crc64(data), digest.sum64());
}
#[test]
fn copy_from_payload_allows_zero_len() {
    let mut out = 0u8;
    let ptr = core::ptr::NonNull::<u8>::dangling().as_ptr();
    let res = unsafe { copy_from_payload(ptr, &mut out as *mut u8, 0) };
    assert!(res.is_ok());
}
#[cfg(feature = "compression")]
#[test]
fn payload_stream_reads_zstd_payload() {
    use std::io::{Cursor, Read};
    let payload = b"payload stream zstd check".to_vec();
    let compressed = zstd::encode_all(Cursor::new(payload.clone()), 0).expect("compress payload");
    let cursor = Cursor::new(compressed);
    let mut stream =
        stream::PayloadStream::new(cursor, Compression::Zstd).expect("create zstd stream");
    let mut decoded = Vec::new();
    Read::read_to_end(&mut stream, &mut decoded).expect("read zstd payload");
    assert_eq!(decoded, payload);
}
#[test]
fn decode_field_canonical_reports_scalar_consumed() {
    reset_decode_state();
    let mut buf = Vec::new();
    serialize_to_buffer(&0xDEADBEEFu32, &mut buf).unwrap();
    let (value, used) = decode_field_canonical::<u32>(&buf).expect("scalar decode");
    assert_eq!(value, 0xDEADBEEF);
    assert_eq!(used, buf.len());
}
#[test]
fn decode_field_canonical_rejects_trailing_bytes() {
    reset_decode_state();
    let mut bytes = Vec::new();
    serialize_to_buffer(&7_u32, &mut bytes).expect("encode scalar");
    bytes.push(0xFF);
    let error = decode_field_canonical::<u32>(&bytes)
        .expect_err("canonical field decode must consume the complete payload");
    assert!(matches!(error, Error::LengthMismatch));
}

#[test]
fn decode_field_canonical_honors_payload_context_flags() {
    reset_decode_state();
    let expected = CanonicalStruct {
        a: 0x0102_0304,
        b: vec![5, 8, 13],
        c: Some(vec![21, 34]),
    };
    let mut bytes = Vec::new();
    {
        let _flags = DecodeFlagsGuard::enter(0);
        serialize_to_buffer(&expected, &mut bytes).expect("encode fixed-width field frames");
    }
    set_payload_ctx_state(&bytes, None, Some(0));

    let (decoded, used) =
        decode_field_canonical::<CanonicalStruct>(&bytes).expect("decode advertised layout");

    assert_eq!(decoded, expected);
    assert_eq!(used, bytes.len());
    reset_decode_state();
}
#[test]
fn decode_field_prefix_allows_trailing_bytes_and_reports_consumption() {
    reset_decode_state();
    let expected = String::from("prefix value");
    let mut encoded = Vec::new();
    serialize_to_buffer(&expected, &mut encoded).expect("encode string");
    let encoded_len = encoded.len();
    encoded.extend_from_slice(&[0xAA, 0xBB]);
    let (decoded, used) = decode_field_prefix::<String>(&encoded).expect("decode string prefix");
    assert_eq!(decoded, expected);
    assert_eq!(used, encoded_len);
}
#[derive(Clone, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
#[norito(decode_from_slice)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito.test.core.tests.PrefixRecord")]
struct PrefixRecord {
    label: String,
    count: u32,
}
#[test]
fn decode_field_prefix_allows_trailing_bytes_after_a_struct() {
    reset_decode_state();
    let expected = PrefixRecord {
        label: "prefix record".to_owned(),
        count: 17,
    };
    let mut encoded = encode_adaptive(&expected);
    let encoded_len = encoded.len();
    encoded.extend_from_slice(&[0xAA, 0xBB]);
    let (decoded, used) =
        decode_field_prefix::<PrefixRecord>(&encoded).expect("decode struct prefix");
    assert_eq!(decoded, expected);
    assert_eq!(used, encoded_len);
    assert!(matches!(
        decode_field_canonical::<PrefixRecord>(&encoded),
        Err(Error::LengthMismatch)
    ));
}
#[test]
fn isolated_frame_decode_resets_and_restores_the_prefix_boundary() {
    reset_decode_state();
    let expected = PrefixRecord {
        label: "isolated record".repeat(32),
        count: 23,
    };
    let (mut payload, flags) = encode_with_header_flags(&expected);
    assert!(
        payload.len() >= archived_payload_size::<PrefixRecord>(),
        "test payload must exercise direct archived deserialization"
    );
    payload.push(0xAA);
    let frame = frame_bare_with_header_flags::<PrefixRecord>(&payload, flags)
        .expect("frame struct payload with a nonzero tail");
    let _prefix_boundary = FieldDecodeBoundaryGuard::enter(FieldDecodeBoundary::Prefix);
    assert!(matches!(
        decode_from_bytes::<PrefixRecord>(&frame),
        Err(Error::LengthMismatch)
    ));
    assert!(FIELD_DECODE_BOUNDARY.with(|slot| slot.get() == FieldDecodeBoundary::Prefix));
}
#[test]
fn slice_frame_decode_rejects_a_nonzero_logical_tail() {
    reset_decode_state();
    let expected = PrefixRecord {
        label: String::new(),
        count: 29,
    };
    let (mut payload, flags) = encode_with_header_flags(&expected);
    payload.push(0xAA);
    assert!(
        payload.len() < archived_payload_size::<PrefixRecord>(),
        "test payload must exercise slice-based deserialization"
    );
    let frame = frame_bare_with_header_flags::<PrefixRecord>(&payload, flags)
        .expect("frame short struct payload with a nonzero tail");
    assert!(matches!(
        decode_from_bytes::<PrefixRecord>(&frame),
        Err(Error::LengthMismatch)
    ));
}
static FIELD_SLOT_DROPS: AtomicUsize = AtomicUsize::new(0);
#[derive(Debug)]
struct DropAfterLengthMismatch;
impl Drop for DropAfterLengthMismatch {
    fn drop(&mut self) {
        FIELD_SLOT_DROPS.fetch_add(1, Ordering::Relaxed);
    }
}

impl SerializePayload for DropAfterLengthMismatch {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        writer.write_all(&[0])?;
        Ok(())
    }
}

impl<'de> DeserializePayload<'de> for DropAfterLengthMismatch {
    fn deserialize(_archived: &'de Archived<Self>) -> Self {
        Self
    }
}
#[test]
fn erased_field_slot_drops_value_after_consumption_error() {
    FIELD_SLOT_DROPS.store(0, Ordering::Relaxed);
    let error = decode_field_canonical::<DropAfterLengthMismatch>(&[0, 1])
        .expect_err("recomputed canonical length must reject trailing data");
    assert!(matches!(error, Error::LengthMismatch));
    assert_eq!(FIELD_SLOT_DROPS.load(Ordering::Relaxed), 1);
}
#[test]
fn erased_field_decoder_preserves_panic_type_name() {
    #[derive(Debug)]
    struct PanicDuringFieldDecode;

    impl SerializePayload for PanicDuringFieldDecode {
        fn serialize(&self, _encoder: &mut Encoder<'_>) -> Result<(), Error> {
            Ok(())
        }
    }

    impl<'de> DeserializePayload<'de> for PanicDuringFieldDecode {
        fn deserialize(_archived: &'de Archived<Self>) -> Self {
            panic!("intentional field decode panic")
        }
    }
    let error = decode_field_canonical::<PanicDuringFieldDecode>(&[0])
        .expect_err("field decode must suppress the panic");
    assert!(matches!(
        error,
        Error::DecodePanic { context }
            if context == core::any::type_name::<PanicDuringFieldDecode>()
    ));
}
#[test]
fn decode_archived_field_owns_realigns_and_installs_payload_context() {
    reset_decode_state();
    let expected = String::from("shared archived field helper");
    let mut encoded = Vec::new();
    serialize_to_buffer(&expected, &mut encoded).expect("encode string");
    let mut storage = Vec::with_capacity(encoded.len() + 1);
    storage.push(0xAA);
    storage.extend_from_slice(&encoded);
    let misaligned = &storage[1..];
    assert_ne!(
        misaligned.as_ptr() as usize % archived_payload_align::<String>(),
        0,
        "test payload must exercise the realignment path"
    );
    let decoded = decode_archived_field::<String>(misaligned).expect("decode archived field copy");
    assert_eq!(decoded, expected);
}
#[test]
fn decode_archived_field_uses_one_charged_overaligned_copy() {
    static DECODED_ADDRESS: AtomicUsize = AtomicUsize::new(0);
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[repr(C, align(64))]
    struct OveralignedField([u8; 64]);

    impl<'de> DeserializePayload<'de> for OveralignedField {
        fn deserialize(archived: &'de Archived<Self>) -> Self {
            DECODED_ADDRESS.store(
                archived as *const Archived<Self> as usize,
                Ordering::Relaxed,
            );
            let bytes = payload_range_from_ptr(
                core::ptr::from_ref(archived).cast::<u8>(),
                core::mem::size_of::<Self>(),
            )
            .expect("overaligned test field payload");
            let mut field = [0_u8; 64];
            field.copy_from_slice(bytes);
            Self(field)
        }
    }
    assert_eq!(archived_payload_size::<OveralignedField>(), 64);
    let bytes = [0xA5_u8; 64];
    let limits = DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, bytes.len(), usize::MAX);
    let decoded = with_decode_limits(limits, || decode_archived_field::<OveralignedField>(&bytes))
        .expect("one exactly budgeted aligned copy should decode");
    let decoded_address = DECODED_ADDRESS.load(Ordering::Relaxed);
    assert_eq!(decoded, OveralignedField(bytes));
    assert_ne!(decoded_address, bytes.as_ptr() as usize);
    assert_eq!(
        decoded_address % archived_payload_align::<OveralignedField>(),
        0
    );
    DECODED_ADDRESS.store(0, Ordering::Relaxed);
    let limits = DecodeLimits::new(
        usize::MAX,
        usize::MAX,
        usize::MAX,
        bytes.len() - 1,
        usize::MAX,
    );
    let error = with_decode_limits(limits, || decode_archived_field::<OveralignedField>(&bytes))
        .expect_err("the owned copy must consume the active allocation budget");
    assert!(matches!(
        error,
        Error::TotalAllocationExceeded { attempted, limit }
            if attempted == bytes.len() as u64 && limit == (bytes.len() - 1) as u64
    ));
    assert_eq!(
        DECODED_ADDRESS.load(Ordering::Relaxed),
        0,
        "budget rejection must happen before deserialization"
    );
}
#[test]
fn decode_archived_field_charges_padding_and_aligned_copy() {
    #[derive(Debug, PartialEq, Eq)]
    #[repr(C, align(64))]
    struct ShortOveralignedField([u8; 64]);

    impl<'de> DeserializePayload<'de> for ShortOveralignedField {
        fn deserialize(_archived: &'de Archived<Self>) -> Self {
            Self([0; 64])
        }
    }

    let bytes = [0xA5];
    let allocation_bytes = 2 * archived_payload_size::<ShortOveralignedField>();
    let limits = DecodeLimits::new(
        usize::MAX,
        usize::MAX,
        usize::MAX,
        allocation_bytes,
        usize::MAX,
    );
    let (decoded, usage) = with_decode_limits_measured(limits, || {
        decode_archived_field::<ShortOveralignedField>(&bytes)
    });
    assert_eq!(
        decoded.expect("an exact budget must cover padding and its aligned copy"),
        ShortOveralignedField([0; 64])
    );
    assert_eq!(usage.total_allocated_bytes(), allocation_bytes);

    let limits = DecodeLimits::new(
        usize::MAX,
        usize::MAX,
        usize::MAX,
        allocation_bytes - 1,
        usize::MAX,
    );
    let error = with_decode_limits(limits, || {
        decode_archived_field::<ShortOveralignedField>(&bytes)
    })
    .expect_err("one byte less must reject the second temporary allocation");
    assert!(matches!(
        error,
        Error::TotalAllocationExceeded { attempted, limit }
            if attempted == allocation_bytes as u64 && limit == (allocation_bytes - 1) as u64
    ));
}
#[test]
fn decode_archived_field_preserves_deserializer_errors() {
    #[derive(Debug)]
    struct Rejected;

    impl<'de> DeserializePayload<'de> for Rejected {
        fn deserialize(_archived: &'de Archived<Self>) -> Self {
            unreachable!("the fallible implementation is used by the helper")
        }
        fn try_deserialize(_archived: &'de Archived<Self>) -> Result<Self, Error> {
            Err(Error::LengthMismatch)
        }
    }
    let error = decode_archived_field::<Rejected>(&[0])
        .expect_err("fallible archived decoder must reject the payload");
    assert!(matches!(error, Error::LengthMismatch));
}
#[test]
fn decode_archived_field_contains_deserializer_panics() {
    #[derive(Debug)]
    struct PanicDuringArchivedFieldDecode;

    impl<'de> DeserializePayload<'de> for PanicDuringArchivedFieldDecode {
        fn deserialize(_archived: &'de Archived<Self>) -> Self {
            panic!("intentional archived-field panic")
        }
    }
    let error = decode_archived_field::<PanicDuringArchivedFieldDecode>(&[])
        .expect_err("archived-field decoding must contain panics");
    assert!(matches!(
        error,
        Error::DecodePanic { context }
            if context == core::any::type_name::<PanicDuringArchivedFieldDecode>()
    ));
}
#[test]
fn decode_vec_from_slice_serial_reports_prefix_used() {
    reset_decode_state();
    let value = vec![3_u16, 5, 8, 13];
    let bytes = encode_adaptive(&value);
    let mut with_tail = bytes.clone();
    with_tail.extend_from_slice(&[0xAA, 0xBB]);
    let (decoded, used) =
        decode_vec_from_slice_serial::<u16>(&with_tail).expect("decode sequence prefix");
    assert_eq!(decoded, value);
    assert_eq!(used, bytes.len());
    reset_decode_state();
}
#[test]
fn decode_vec_u8_from_slice_serial_reports_prefix_used() {
    reset_decode_state();
    let value = vec![3_u8, 5, 8, 13];
    let bytes = encode_adaptive(&value);
    let mut with_tail = bytes.clone();
    with_tail.extend_from_slice(&[0xAA, 0xBB]);
    let (decoded, used) =
        decode_vec_from_slice_serial::<u8>(&with_tail).expect("decode byte sequence prefix");
    assert_eq!(decoded, value);
    assert_eq!(used, bytes.len());
    assert!(matches!(
        decode_field_canonical::<Vec<u8>>(&with_tail),
        Err(Error::LengthMismatch)
    ));
    reset_decode_state();
}
#[test]
fn decode_generic_u8_sequence_preserves_element_lengths_and_prefix_boundary() {
    reset_decode_state();
    let _guard = DecodeFlagsGuard::enter(0);
    let value = [3_u8, 5, 8, 13];
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(value.len() as u64).to_le_bytes());
    for byte in value {
        bytes.extend_from_slice(&1_u64.to_le_bytes());
        bytes.push(byte);
    }
    let sequence_len = bytes.len();
    bytes.extend_from_slice(&[0xAA, 0xBB]);
    let (decoded, used) = decode_element_sequence_from_slice_serial::<u8>(&bytes)
        .expect("decode generic byte element sequence");
    assert_eq!(decoded, value);
    assert_eq!(used, sequence_len);
    assert!(matches!(
        decode_field_canonical::<Vec<u8>>(&bytes[..sequence_len]),
        Err(Error::LengthMismatch)
    ));
    reset_decode_state();
}
#[test]
fn generic_sequence_decode_charges_count_once_and_has_an_exact_allocation_boundary() {
    reset_decode_state();
    let _guard = DecodeFlagsGuard::enter(0);
    let value = [3_u16, 5, 8, 13];
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(value.len() as u64).to_le_bytes());
    for element in value {
        bytes.extend_from_slice(&2_u64.to_le_bytes());
        bytes.extend_from_slice(&element.to_le_bytes());
    }

    let permissive = DecodeLimits::new(
        value.len(),
        usize::MAX,
        value.len(),
        usize::MAX,
        MAX_VALUE_NESTING_DEPTH,
    );
    let (decoded, usage) = with_decode_limits_measured(permissive, || {
        decode_element_sequence_from_slice_serial::<u16>(&bytes)
    });
    assert_eq!(decoded.expect("decode measured generic sequence").0, value);
    assert_eq!(usage.total_elements(), value.len());
    let allocation_bytes = usage.total_allocated_bytes();
    assert!(allocation_bytes > 0);

    let exact = DecodeLimits::new(
        value.len(),
        usize::MAX,
        value.len(),
        allocation_bytes,
        MAX_VALUE_NESTING_DEPTH,
    );
    let decoded = with_decode_limits(exact, || {
        decode_element_sequence_from_slice_serial::<u16>(&bytes)
    })
    .expect("the measured allocation budget must be sufficient");
    assert_eq!(decoded.0, value);

    let one_byte_short = DecodeLimits::new(
        value.len(),
        usize::MAX,
        value.len(),
        allocation_bytes - 1,
        MAX_VALUE_NESTING_DEPTH,
    );
    let error = with_decode_limits(one_byte_short, || {
        decode_element_sequence_from_slice_serial::<u16>(&bytes)
    })
    .expect_err("one byte less than the measured allocation must fail");
    assert!(matches!(
        error,
        Error::TotalAllocationExceeded { attempted, limit }
            if attempted == allocation_bytes as u64 && limit == (allocation_bytes - 1) as u64
    ));
    reset_decode_state();
}
#[test]
fn decode_vec_u8_from_slice_reports_prefix_used() {
    reset_decode_state();
    let value = vec![3_u8, 5, 8, 13];
    let bytes = encode_adaptive(&value);
    let mut with_tail = bytes.clone();
    with_tail.extend_from_slice(&[0xAA, 0xBB]);
    let (decoded, used) =
        decode_field_prefix::<Vec<u8>>(&with_tail).expect("decode raw byte sequence prefix");
    assert_eq!(decoded, value);
    assert_eq!(used, bytes.len());
    assert!(matches!(
        decode_field_canonical::<Vec<u8>>(&with_tail),
        Err(Error::LengthMismatch)
    ));
    reset_decode_state();
}
#[test]
fn decode_field_canonical_propagates_access_to_parent_ctx() {
    reset_decode_state();
    let mut buf = Vec::new();
    serialize_to_buffer(&0xAABBCCDDu32, &mut buf).unwrap();
    let _outer = PayloadCtxGuard::enter(&buf);
    let (value, used) = decode_field_canonical::<u32>(&buf).expect("scalar decode");
    assert_eq!(value, 0xAABBCCDD);
    assert_eq!(used, buf.len());
    assert_eq!(
        payload_ctx_max_access().unwrap(),
        buf.len(),
        "outer payload ctx must observe canonical consumption"
    );
}
#[test]
fn decode_field_canonical_propagates_access_from_misaligned_copy() {
    reset_decode_state();
    let mut buf = Vec::new();
    serialize_to_buffer(&0xDEADBEEFu32, &mut buf).unwrap();
    let mut storage = Vec::with_capacity(buf.len() + 1);
    storage.push(0xAA);
    storage.extend_from_slice(&buf);
    let misaligned = &storage[1..];
    assert_ne!(
        misaligned.as_ptr() as usize % archived_payload_align::<u32>(),
        0,
        "expected misaligned scalar payload"
    );
    let _outer = PayloadCtxGuard::enter(misaligned);
    let (value, used) =
        decode_field_canonical::<u32>(misaligned).expect("decode misaligned scalar");
    assert_eq!(value, 0xDEADBEEF);
    assert_eq!(used, misaligned.len());
    assert_eq!(
        payload_ctx_max_access().unwrap(),
        misaligned.len(),
        "outer payload ctx must observe canonical consumption from misaligned decode"
    );
}
thread_local! {
    // Each libtest thread owns its decode-recomputation sentinel.
    static PANIC_ON_SERIALIZE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}
#[test]
fn decode_recomputation_sentinels_are_isolated_between_threads() {
    let barrier = std::sync::Barrier::new(2);
    std::thread::scope(|scope| {
        scope.spawn(|| {
            PANIC_ON_SERIALIZE.set(true);
            barrier.wait();
            barrier.wait();
            assert!(PANIC_ON_SERIALIZE.get());
            PANIC_ON_SERIALIZE.set(false);
        });
        scope.spawn(|| {
            barrier.wait();
            let other_thread_is_clear = !PANIC_ON_SERIALIZE.get();
            barrier.wait();
            assert!(other_thread_is_clear);
        });
    });
}
#[derive(Clone, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
struct CanonicalStruct {
    a: u32,
    b: Vec<u64>,
    c: Option<Vec<u8>>,
}
#[repr(transparent)]
#[derive(Clone, Debug, PartialEq, Eq)]
struct CanonicalStructNoRecompute(CanonicalStruct);

impl SerializePayload for CanonicalStructNoRecompute {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        if PANIC_ON_SERIALIZE.get() {
            panic!("serialize called during canonical decode recompute");
        }
        self.0.serialize(writer)
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        self.0.encoded_len_hint()
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        self.0.encoded_len_exact()
    }
}

impl<'a> DeserializePayload<'a> for CanonicalStructNoRecompute {
    fn deserialize(archived: &'a Archived<Self>) -> Self {
        Self::try_deserialize(archived).expect("CanonicalStructNoRecompute decode")
    }
    fn try_deserialize(archived: &'a Archived<Self>) -> Result<Self, Error> {
        let value = CanonicalStruct::try_deserialize(archived.cast::<CanonicalStruct>())?;
        Ok(Self(value))
    }
}
#[test]
fn decode_field_canonical_does_not_recompute_for_derived_struct() {
    PANIC_ON_SERIALIZE.set(false);
    reset_decode_state();
    let value = CanonicalStructNoRecompute(CanonicalStruct {
        a: 0xAABBCCDD,
        b: vec![1, 2, 3, 4, 5],
        c: Some(vec![9, 8, 7]),
    });
    let encoded = encode_adaptive(&value);
    PANIC_ON_SERIALIZE.set(true);
    let (decoded, used) =
        decode_field_canonical::<CanonicalStructNoRecompute>(&encoded).expect("decode struct");
    assert_eq!(used, encoded.len());
    assert_eq!(decoded, value);
    PANIC_ON_SERIALIZE.set(false);
}
#[derive(Clone, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(iroha_schema::TypeId))]
enum CanonicalEnum {
    Unit,
    One(u32),
    Many { a: u32, b: Vec<u8> },
}

// Preserve the named codec variant while describing its actual schema fields.
#[cfg(feature = "schema-structural")]
#[derive(iroha_schema::IntoSchema)]
#[allow(dead_code)]
struct CanonicalEnumManyFields {
    a: u32,
    b: Vec<u8>,
}

#[cfg(feature = "schema-structural")]
impl iroha_schema::IntoSchema for CanonicalEnum {
    fn type_name() -> String {
        "CanonicalEnum".to_owned()
    }

    fn update_schema_map(map: &mut iroha_schema::MetaMap) {
        if map.contains_key::<Self>() {
            return;
        }
        map.insert::<Self>(iroha_schema::Metadata::Enum(iroha_schema::EnumMeta {
            variants: vec![
                iroha_schema::EnumVariant {
                    tag: "Unit".to_owned(),
                    discriminant: 0,
                    ty: None,
                },
                iroha_schema::EnumVariant {
                    tag: "One".to_owned(),
                    discriminant: 1,
                    ty: Some(std::any::TypeId::of::<u32>()),
                },
                iroha_schema::EnumVariant {
                    tag: "Many".to_owned(),
                    discriminant: 2,
                    ty: Some(std::any::TypeId::of::<CanonicalEnumManyFields>()),
                },
            ],
        }));
        <u32 as iroha_schema::IntoSchema>::update_schema_map(map);
        CanonicalEnumManyFields::update_schema_map(map);
    }
}
#[repr(transparent)]
#[derive(Clone, Debug, PartialEq, Eq)]
struct CanonicalEnumNoRecompute(CanonicalEnum);

impl SerializePayload for CanonicalEnumNoRecompute {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        if PANIC_ON_SERIALIZE.get() {
            panic!("serialize called during canonical decode recompute");
        }
        self.0.serialize(writer)
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        self.0.encoded_len_hint()
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        self.0.encoded_len_exact()
    }
}

impl<'a> DeserializePayload<'a> for CanonicalEnumNoRecompute {
    fn deserialize(archived: &'a Archived<Self>) -> Self {
        Self::try_deserialize(archived).expect("CanonicalEnumNoRecompute decode")
    }
    fn try_deserialize(archived: &'a Archived<Self>) -> Result<Self, Error> {
        let value = CanonicalEnum::try_deserialize(archived.cast::<CanonicalEnum>())?;
        Ok(Self(value))
    }
}
#[test]
fn decode_field_canonical_does_not_recompute_for_derived_enum() {
    PANIC_ON_SERIALIZE.set(false);
    reset_decode_state();
    let value = CanonicalEnumNoRecompute(CanonicalEnum::Many {
        a: 0x01020304,
        b: vec![0xAA, 0xBB, 0xCC],
    });
    let encoded = encode_adaptive(&value);
    PANIC_ON_SERIALIZE.set(true);
    let (decoded, used) =
        decode_field_canonical::<CanonicalEnumNoRecompute>(&encoded).expect("decode enum");
    assert_eq!(used, encoded.len());
    assert_eq!(decoded, value);
    PANIC_ON_SERIALIZE.set(false);
}
#[test]
fn decode_field_canonical_handles_misaligned_payload() {
    let value: Vec<Vec<u64>> = vec![vec![1, 2, 3], vec![], vec![4, 5]];
    let encoded = encode_adaptive(&value);
    let mut storage = Vec::with_capacity(encoded.len() + 1);
    storage.push(0xAA);
    storage.extend_from_slice(&encoded);
    let misaligned = &storage[1..];
    assert_ne!(
        misaligned.as_ptr() as usize % archived_payload_align::<Vec<Vec<u64>>>(),
        0,
        "expected misaligned test payload"
    );
    let (decoded, used) =
        decode_field_canonical::<Vec<Vec<u64>>>(misaligned).expect("decode misaligned field");
    assert_eq!(decoded, value);
    assert_eq!(used, encoded.len());
}
#[path = "borrowed_field_framing_tests.rs"]
mod borrowed_field_framing_tests;
#[path = "prepared_slice_prefix_tests.rs"]
mod prepared_slice_prefix_tests;

#[test]
fn context_field_helpers_decode_framed_fields_and_require_full_consumption() {
    reset_decode_state();
    let first = 0x0102_0304_u32;
    let second = 0xA0B0_C0D0_u32;
    let mut first_bytes = Vec::new();
    let mut second_bytes = Vec::new();
    serialize_to_buffer(&first, &mut first_bytes).expect("encode first");
    serialize_to_buffer(&second, &mut second_bytes).expect("encode second");
    let mut payload = Vec::new();
    write_len(&mut payload, first_bytes.len() as u64).expect("frame first");
    payload.extend_from_slice(&first_bytes);
    write_len(&mut payload, second_bytes.len() as u64).expect("frame second");
    payload.extend_from_slice(&second_bytes);
    let _guard = PayloadCtxGuard::enter(&payload);
    let mut offset = 0;
    assert_eq!(
        decode_context_field_canonical::<u32>(payload.as_ptr(), &mut offset).expect("decode first"),
        first
    );
    assert_eq!(
        decode_context_field_canonical::<u32>(payload.as_ptr(), &mut offset)
            .expect("decode second"),
        second
    );
    finish_context_fields(payload.as_ptr(), offset).expect("consume payload");
    assert!(matches!(
        finish_context_fields(payload.as_ptr(), offset - 1),
        Err(Error::LengthMismatch)
    ));
}
#[test]
fn context_field_helpers_bound_declared_lengths_before_decoding() {
    reset_decode_state();
    let mut payload = Vec::new();
    write_len(&mut payload, 1024).expect("write oversized field length");
    payload.push(0xAA);
    let _guard = PayloadCtxGuard::enter(&payload);
    let mut offset = 0;
    assert!(matches!(
        decode_context_field_canonical::<u32>(payload.as_ptr(), &mut offset),
        Err(Error::LengthMismatch)
    ));
    assert_eq!(offset, 0, "a rejected frame must not consume input");
    drop(_guard);
    let mut malformed = Vec::new();
    write_len(&mut malformed, 1).expect("write short field length");
    malformed.push(0xAA);
    let _guard = PayloadCtxGuard::enter(&malformed);
    assert!(matches!(
        decode_context_field_canonical::<u32>(malformed.as_ptr(), &mut offset),
        Err(Error::LengthMismatch)
    ));
    assert_eq!(
        offset, 0,
        "a framed value that fails typed decoding must not consume input"
    );
}
#[test]
fn canonical_context_field_rejects_trailing_bytes_inside_declared_frame() {
    reset_decode_state();
    let mut field = Vec::new();
    serialize_to_buffer(&0x0102_0304_u32, &mut field).expect("encode field");
    field.push(0xAA);
    let mut payload = Vec::new();
    write_len(&mut payload, field.len() as u64).expect("frame field");
    payload.extend_from_slice(&field);
    let _guard = PayloadCtxGuard::enter(&payload);
    let mut offset = 0;
    assert!(matches!(
        decode_context_field_canonical::<u32>(payload.as_ptr(), &mut offset),
        Err(Error::LengthMismatch)
    ));
    assert_eq!(offset, 0, "a non-canonical frame must not consume input");
}
#[test]
fn context_field_and_fixed_array_helpers_advance_exactly() {
    reset_decode_state();
    let first = String::from("alpha");
    let second = String::from("beta");
    let mut payload = Vec::new();
    for value in [&first, &second] {
        let mut field = Vec::new();
        serialize_to_buffer(value, &mut field).expect("encode string field");
        write_len(&mut payload, field.len() as u64).expect("frame field");
        payload.extend_from_slice(&field);
    }
    payload.extend_from_slice(&[1, 2, 3, 4]);
    let _guard = PayloadCtxGuard::enter(&payload);
    let mut offset = 0;
    assert_eq!(
        decode_context_field_canonical::<String>(payload.as_ptr(), &mut offset)
            .expect("decode first field"),
        first
    );
    assert_eq!(
        decode_context_field_canonical::<String>(payload.as_ptr(), &mut offset)
            .expect("decode second field"),
        second
    );
    assert_eq!(
        decode_context_byte_array::<4>(payload.as_ptr(), &mut offset).expect("decode fixed bytes"),
        [1, 2, 3, 4]
    );
    finish_context_fields(payload.as_ptr(), offset).expect("consume payload");
}
#[test]
fn note_payload_access_updates_max_access() {
    reset_decode_state();
    let payload: Vec<u8> = (0..32).collect();
    let _guard = PayloadCtxGuard::enter(&payload);
    note_payload_access(&payload, payload.len());
    assert_eq!(payload_ctx_max_access().unwrap(), payload.len());
}
#[test]
fn decode_field_canonical_from_slice_reads_value() {
    let mut buf = Vec::new();
    serialize_to_buffer(&0xAABBCCDDu32, &mut buf).expect("encode");
    let (value, used) = decode_field_canonical_from_slice::<u32>(&buf).expect("decode slice");
    assert_eq!(value, 0xAABBCCDD);
    assert_eq!(used, buf.len());
}
#[test]
fn decode_field_canonical_slice_reads_value() {
    let mut buf = Vec::new();
    serialize_to_buffer(&0xDEADBEEFu32, &mut buf).expect("encode");
    let (value, used) = decode_field_canonical_slice::<u32>(&buf).expect("decode slice");
    assert_eq!(value, 0xDEADBEEF);
    assert_eq!(used, buf.len());
}
#[test]
fn decode_field_canonical_from_slice_rejects_trailing_bytes() {
    let mut buf = Vec::new();
    serialize_to_buffer(&7u32, &mut buf).expect("encode");
    buf.push(0xFF);
    let err = decode_field_canonical_from_slice::<u32>(&buf).expect_err("trailing bytes");
    assert!(matches!(err, Error::LengthMismatch));
}
#[test]
fn to_bytes_in_matches_to_bytes() {
    let value: Vec<u64> = vec![1, 2, 3, 4];
    let mut out = Vec::with_capacity(128);
    to_bytes_in(&value, &mut out).expect("encode to buffer");
    let expected = to_bytes(&value).expect("encode expected");
    assert_eq!(out, expected);
    let cap = out.capacity();
    to_bytes_in(&value, &mut out).expect("encode to buffer again");
    assert!(out.capacity() >= cap);
}
#[test]
fn byte_sink_with_headroom_from_preserves_capacity() {
    let mut buf = Vec::with_capacity(2048);
    buf.extend_from_slice(&[1u8, 2, 3, 4]);
    let cap = buf.capacity();
    let sink = ByteSink::with_headroom_from(buf, 16, Header::SIZE);
    assert_eq!(sink.buf.len(), Header::SIZE);
    assert!(sink.buf.capacity() >= cap);
}
#[derive(Clone, Copy, Debug, PartialEq)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
#[cfg_attr(feature = "schema-structural", schema(transparent = "u32"))]
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito.test.core.tests.BadExactLen")]
struct BadExactLen(u32);

impl crate::SerializePayload for BadExactLen {
    fn serialize(&self, encoder: &mut Encoder<'_>) -> Result<(), Error> {
        crate::SerializePayload::serialize(&self.0, encoder)
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        Some(1)
    }
}

impl<'de> crate::DeserializePayload<'de> for BadExactLen {
    fn deserialize(archived: &'de Archived<Self>) -> Self {
        Self::try_deserialize(archived).expect("BadExactLen decode must succeed")
    }
    fn try_deserialize(archived: &'de Archived<Self>) -> Result<Self, Error> {
        let ptr = core::ptr::from_ref(archived).cast::<u8>();
        let payload = payload_slice_from_ptr(ptr)?;
        let (value, _) = decode_field_canonical::<u32>(payload)?;
        Ok(BadExactLen(value))
    }
}
impl<'a> DecodeFromSlice<'a> for BadExactLen {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), Error> {
        let (value, used) = decode_field_canonical::<u32>(bytes)?;
        Ok((BadExactLen(value), used))
    }
}
const HOSTILE_GROWTH_CHUNK_BYTES: usize = 4 * 1024;
const HOSTILE_GROWTH_WRITES: usize = 256;
struct HostileGrowingSecondPass(std::cell::Cell<usize>);

impl SerializePayload for HostileGrowingSecondPass {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        let pass = self.0.get();
        self.0.set(pass + 1);
        writer.write_all(&[0x11])?;
        if pass != 0 {
            for _ in 0..HOSTILE_GROWTH_WRITES {
                writer.write_all(&[0x22; HOSTILE_GROWTH_CHUNK_BYTES])?;
            }
        }
        Ok(())
    }
}
#[test]
fn decode_field_canonical_ignores_bad_encoded_len_exact() {
    let value = BadExactLen(0xAABBCCDD);
    let encoded = encode_adaptive(&value);
    let (decoded, used) =
        decode_field_canonical::<BadExactLen>(&encoded).expect("decode bad exact len");
    assert_eq!(decoded, value);
    assert_eq!(used, encoded.len());
}
#[test]
fn encoded_frame_len_ignores_bad_encoded_len_exact() {
    let value = BadExactLen(0xAABBCCDD);
    assert_eq!(
        encoded_frame_len(&value).expect("count canonical frame"),
        to_bytes(&value).expect("encode canonical frame").len()
    );
}
#[test]
fn encoded_payload_len_ignores_bad_encoded_len_exact() {
    let value = BadExactLen(0xAABBCCDD);
    assert_eq!(
        encoded_payload_len(&value).expect("count canonical payload"),
        core::mem::size_of::<u32>()
    );
}
#[test]
fn bounded_frame_matches_canonical_bytes_at_exact_limit() {
    let value = vec![1_u64, 2, 3, 5, 8, 13];
    let canonical = to_bytes(&value).expect("encode canonical frame");
    let bounded =
        to_bytes_bounded(&value, canonical.len()).expect("encode canonical frame at exact bound");
    assert_eq!(bounded, canonical);
    assert_eq!(bounded.capacity(), bounded.len());
}
#[test]
fn bounded_frame_rejects_one_byte_below_real_count_before_second_pass() {
    use std::cell::Cell;
    #[derive(crate::NoritoSchema)]
    #[norito_schema(name = "norito.test.core.tests.CountCalls")]
    struct CountCalls(Cell<usize>);

    impl SerializePayload for CountCalls {
        fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
            self.0.set(self.0.get() + 1);
            writer.write_all(&[0xA5])?;
            Ok(())
        }
    }
    let value = CountCalls(Cell::new(0));
    let exact = Header::SIZE + payload_alignment_padding_for::<CountCalls>() + 1;
    assert!(matches!(
        to_bytes_bounded(&value, exact - 1),
        Err(BoundedEncodeError::FrameTooLarge {
            encoded_bytes,
            max_bytes,
        }) if encoded_bytes == exact && max_bytes == exact - 1
    ));
    assert_eq!(
        value.0.get(),
        1,
        "oversized frames must not run an output pass"
    );
}
#[test]
fn bounded_frame_rejects_second_pass_growth_past_counted_capacity() {
    use std::cell::Cell;
    #[derive(crate::NoritoSchema)]
    #[norito_schema(name = "norito.test.core.tests.GrowingSecondPass")]
    struct GrowingSecondPass(Cell<usize>);

    impl SerializePayload for GrowingSecondPass {
        fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
            let pass = self.0.get();
            self.0.set(pass + 1);
            writer.write_all(if pass == 0 { &[0x11] } else { &[0x11, 0x22] })?;
            Ok(())
        }
    }
    let value = GrowingSecondPass(Cell::new(0));
    let exact = Header::SIZE + payload_alignment_padding_for::<GrowingSecondPass>() + 1;
    assert!(matches!(
        to_bytes_bounded(&value, exact),
        Err(BoundedEncodeError::Serialization(Error::LengthMismatch))
    ));
    assert_eq!(value.0.get(), 2);
}
#[test]
fn bounded_frame_rejects_second_pass_shrinkage() {
    use std::cell::Cell;
    #[derive(crate::NoritoSchema)]
    #[norito_schema(name = "norito.test.core.tests.ShrinkingSecondPass")]
    struct ShrinkingSecondPass(Cell<usize>);

    impl SerializePayload for ShrinkingSecondPass {
        fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
            let pass = self.0.get();
            self.0.set(pass + 1);
            writer.write_all(if pass == 0 { &[0x11, 0x22] } else { &[0x11] })?;
            Ok(())
        }
    }
    let value = ShrinkingSecondPass(Cell::new(0));
    let exact = Header::SIZE + payload_alignment_padding_for::<ShrinkingSecondPass>() + 2;
    assert!(matches!(
        to_bytes_bounded(&value, exact),
        Err(BoundedEncodeError::Serialization(Error::LengthMismatch))
    ));
    assert_eq!(value.0.get(), 2);
}
#[test]
fn write_len_prefixed_uses_actual_length() {
    let value = BadExactLen(0xDEADBEEF);
    let mut out = Vec::new();
    let mut encoder = Encoder::for_buffer(&mut out);
    write_len_prefixed(&mut encoder, &value).expect("write len prefixed");
    let (len, hdr) = read_len_from_slice(&out).expect("read len");
    assert_eq!(len, out.len() - hdr);
}
#[test]
fn write_len_prefixed_streams_unhinted_field_without_staging() {
    struct UnhintedField<'a> {
        bytes: &'a [u8],
        visits: std::cell::Cell<usize>,
    }

    impl SerializePayload for UnhintedField<'_> {
        fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
            self.visits.set(self.visits.get() + 1);
            writer.write_all(self.bytes)?;
            Ok(())
        }
    }
    struct DirectFieldWriter<'a> {
        payload: &'a [u8],
        prefix: [u8; 9],
        prefix_len: usize,
        payload_writes: usize,
    }
    impl Write for DirectFieldWriter<'_> {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len() == self.payload.len() {
                assert!(
                    core::ptr::eq(bytes.as_ptr(), self.payload.as_ptr()),
                    "the original payload slice must reach the destination directly"
                );
                assert_eq!(bytes, self.payload);
                self.payload_writes += 1;
            } else {
                assert_eq!(
                    self.payload_writes, 0,
                    "the length must precede the payload"
                );
                let end = self.prefix_len + bytes.len();
                self.prefix[self.prefix_len..end].copy_from_slice(bytes);
                self.prefix_len = end;
            }
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let bytes = vec![0x5a; 1536];
    let value = UnhintedField {
        bytes: &bytes,
        visits: std::cell::Cell::new(0),
    };
    assert_eq!(value.encoded_len_exact(), None);
    let mut destination = DirectFieldWriter {
        payload: &bytes,
        prefix: [0; 9],
        prefix_len: 0,
        payload_writes: 0,
    };
    {
        let mut encoder = Encoder::new(&mut destination);
        write_len_prefixed(&mut encoder, &value).expect("write unhinted field");
    }
    let (len, header_bytes) = read_len_from_slice(&destination.prefix[..destination.prefix_len])
        .expect("read field length");
    assert_eq!(len, bytes.len());
    assert_eq!(header_bytes, destination.prefix_len);
    assert_eq!(destination.payload_writes, 1);
    assert_eq!(
        value.visits.get(),
        2,
        "one measurement and one checked write"
    );
}
#[test]
fn write_len_prefixed_rejects_a_changed_second_pass() {
    let value = HostileGrowingSecondPass(std::cell::Cell::new(0));
    let mut out = Vec::with_capacity(32);
    let initial_capacity = out.capacity();
    let error = {
        let mut encoder = Encoder::for_buffer(&mut out);
        write_len_prefixed(&mut encoder, &value).expect_err("second-pass growth must fail")
    };
    assert!(matches!(error, Error::LengthMismatch));
    assert_eq!(value.0.get(), 2);
    let (declared, header_bytes) = read_len_from_slice(&out).expect("declared field length");
    assert_eq!(declared, 1);
    assert_eq!(&out[header_bytes..], &[0x11]);
    assert_eq!(out.capacity(), initial_capacity);
}
#[test]
fn serialize_to_writer_exact_rejects_growth_before_forwarding_it() {
    let value = HostileGrowingSecondPass(std::cell::Cell::new(0));
    let expected = encoded_payload_len(&value).expect("count hostile payload");
    assert_eq!(expected, 1);
    let mut out = Vec::with_capacity(8);
    let initial_capacity = out.capacity();
    assert!(matches!(
        serialize_to_writer_exact(&value, &mut out, expected),
        Err(Error::LengthMismatch)
    ));
    assert_eq!(value.0.get(), 2);
    assert_eq!(out, [0x11]);
    assert_eq!(out.capacity(), initial_capacity);
}
#[derive(Clone, Debug, PartialEq, crate::Encode, crate::Decode)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito.test.core.tests.BadExactWrapper")]
struct BadExactWrapper {
    inner: BadExactLen,
}
#[derive(Clone, Debug, PartialEq, crate::Encode, crate::Decode)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito.test.core.tests.BadExactEnum")]
enum BadExactEnum {
    One(BadExactLen),
}
#[test]
fn derived_struct_ignores_untrusted_exact_field_length() {
    let value = BadExactWrapper {
        inner: BadExactLen(0xAABBCCDD),
    };
    let frame = to_bytes(&value).expect("counted encoding ignores the untrusted length oracle");
    let archived = from_bytes::<BadExactWrapper>(&frame).expect("validate counted struct frame");
    let decoded = BadExactWrapper::try_deserialize(archived).expect("decode counted struct");
    assert_eq!(decoded, value);
}
#[test]
fn derived_enum_ignores_untrusted_exact_field_length() {
    let value = BadExactEnum::One(BadExactLen(0x11223344));
    let frame = to_bytes(&value).expect("counted encoding ignores the untrusted length oracle");
    let archived = from_bytes::<BadExactEnum>(&frame).expect("validate counted enum frame");
    let decoded = BadExactEnum::try_deserialize(archived).expect("decode counted enum");
    assert_eq!(decoded, value);
}

#[derive(crate::Encode)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito.test.core.tests.RecursiveEncodeNode")]
struct RecursiveEncodeNode {
    children: Vec<Self>,
}

#[test]
fn recursive_encode_fails_before_exhausting_the_native_stack() {
    let mut value = RecursiveEncodeNode {
        children: Vec::new(),
    };
    for _ in 0..=MAX_VALUE_NESTING_DEPTH {
        value = RecursiveEncodeNode {
            children: vec![value],
        };
    }
    assert!(
        value.encoded_len_exact().is_none(),
        "recursive length oracles must stop at the canonical nesting ceiling"
    );
    assert!(matches!(
        to_bytes(&value),
        Err(Error::NestingDepthExceeded {
            depth,
            limit: MAX_VALUE_NESTING_DEPTH,
            context: "encode budget",
        }) if depth == MAX_VALUE_NESTING_DEPTH + 1
    ));
}
#[test]
fn truncated_derived_enum_tag_is_a_length_error() {
    let error = decode_archived_field::<BadExactEnum>(&[])
        .expect_err("an enum archive without its four-byte tag must be rejected");
    assert!(matches!(error, Error::LengthMismatch));
}
#[test]
fn result_uses_actual_length_prefix() {
    let value: Result<BadExactLen, BadExactLen> = Ok(BadExactLen(0x01020304));
    let bytes = encode_adaptive(&value);
    let decoded: Result<BadExactLen, BadExactLen> =
        codec::decode_adaptive(&bytes).expect("decode result");
    assert_eq!(decoded, value);
}
#[derive(Clone, Copy)]
struct RootAware(u32);

impl crate::SerializePayload for RootAware {
    fn serialize(&self, encoder: &mut Encoder<'_>) -> Result<(), Error> {
        crate::SerializePayload::serialize(&self.0, encoder)
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        crate::SerializePayload::encoded_len_hint(&self.0)
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        crate::SerializePayload::encoded_len_exact(&self.0)
    }
}

impl<'de> crate::DeserializePayload<'de> for RootAware {
    fn deserialize(archived: &'de Archived<Self>) -> Self {
        Self::try_deserialize(archived).expect("RootAware decode must succeed")
    }
    fn try_deserialize(archived: &'de Archived<Self>) -> Result<Self, Error> {
        let ptr = core::ptr::from_ref(archived).cast::<u8>();
        let payload = payload_slice_from_ptr(ptr)?;
        let (value, _) = decode_field_canonical::<u32>(payload)?;
        Ok(RootAware(value))
    }
}
#[test]
fn decode_field_canonical_installs_root_span() {
    let (payload, flags) = encode_with_header_flags(&RootAware(99));
    let _flags_guard = DecodeFlagsGuard::enter(flags);
    let (decoded, used) = decode_field_canonical::<RootAware>(&payload).expect("root-aware decode");
    assert_eq!(used, payload.len());
    assert_eq!(decoded.0, 99);
}
#[test]
fn archived_from_slice_rejects_truncated_payload() {
    let bytes = [0_u8; core::mem::size_of::<u128>() - 1];
    let error = match archived_from_slice::<u128>(&bytes) {
        Ok(_) => panic!("undersized archived payload must be rejected"),
        Err(error) => error,
    };
    assert!(matches!(error, Error::LengthMismatch));
}
#[test]
fn archived_cast_is_an_opaque_address_marker_and_cannot_bypass_bounds() {
    assert_eq!(core::mem::size_of::<Archived<u8>>(), 0);
    assert_eq!(core::mem::size_of::<Archived<[u8; 4096]>>(), 0);
    assert_eq!(core::mem::align_of::<Archived<u8>>(), 1);
    assert_eq!(core::mem::align_of::<Archived<[u128; 8]>>(), 1);
    let payload = [0xA5_u8];
    let archived = archived_from_slice::<u8>(&payload).expect("one-byte archive");
    let retagged = archived.cast::<u64>();
    assert_eq!(
        core::ptr::from_ref(archived.archived()).cast::<u8>(),
        core::ptr::from_ref(retagged).cast::<u8>()
    );
    let missing =
        <u64 as DeserializePayload>::try_deserialize(retagged).expect_err("context is required");
    assert!(matches!(missing, Error::MissingPayloadContext));
    let _payload = PayloadCtxGuard::enter(archived.bytes());
    let bounded = <u64 as DeserializePayload>::try_deserialize(retagged)
        .expect_err("a cast cannot enlarge the active payload");
    assert!(matches!(bounded, Error::LengthMismatch));
    drop(_payload);
    let empty = archived_from_slice::<()>(&[]).expect("empty archive marker");
    let option = empty.cast::<Option<u64>>();
    let missing = <Option<u64> as DeserializePayload>::try_deserialize(option)
        .expect_err("an opaque empty marker cannot be read without a payload context");
    assert!(matches!(missing, Error::MissingPayloadContext));
    let _empty_payload = PayloadCtxGuard::enter(empty.bytes());
    let bounded = <Option<u64> as DeserializePayload>::try_deserialize(option)
        .expect_err("an opaque empty marker cannot provide an option tag");
    assert!(matches!(bounded, Error::LengthMismatch));
}
#[test]
fn archived_from_slice_propagates_realign_allocation_limit() {
    let align = archived_payload_align::<u128>();
    let mut storage = vec![0_u8; core::mem::size_of::<u128>() + align];
    let base = storage.as_mut_ptr() as usize;
    let offset = (0..align)
        .find(|offset| !(base + offset).is_multiple_of(align))
        .expect("u128 has a misaligned offset");
    let end = offset + core::mem::size_of::<u128>();
    let misaligned = &storage[offset..end];
    let limits = DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX);
    let error = with_decode_limits(limits, || {
        archived_from_slice::<u128>(misaligned).map(|_| ())
    })
    .expect_err("realignment must honor the active allocation limit");
    assert!(matches!(
        error,
        Error::TotalAllocationExceeded {
            attempted,
            limit: 0
        } if attempted == core::mem::size_of::<u128>() as u64
    ));
}

#[test]
fn archived_from_slice_does_not_overalign_borrowed_payload() {
    let type_align = archived_payload_align::<u64>();
    let excessive_align = core::mem::align_of::<u128>();
    if excessive_align <= type_align {
        return;
    }
    let mut storage = vec![0_u8; core::mem::size_of::<u64>() + excessive_align];
    let base = storage.as_mut_ptr() as usize;
    let offset = (0..excessive_align)
        .find(|offset| {
            (base + offset).is_multiple_of(type_align)
                && !(base + offset).is_multiple_of(excessive_align)
        })
        .expect("find payload aligned for u64 but not u128");
    let end = offset + core::mem::size_of::<u64>();
    let payload = &storage[offset..end];
    let archived = archived_from_slice::<u64>(payload).expect("borrow type-aligned payload");
    assert_eq!(
        archived.bytes().as_ptr(),
        payload.as_ptr(),
        "type-aligned payload should not be copied solely for u128 alignment"
    );
}

#[test]
fn archived_from_slice_realigns_payload() {
    #[derive(Debug, PartialEq, NoritoSerialize, NoritoDeserialize)]
    #[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
    struct AlignSensitive {
        data: Vec<u128>,
    }
    reset_decode_state();
    let value = AlignSensitive {
        data: vec![11_u128, 22, 33, 44],
    };
    let (payload, flags) = encode_with_header_flags(&value);
    let mut storage = Vec::with_capacity(payload.len() + 1);
    storage.push(0u8);
    storage.extend_from_slice(&payload);
    let misaligned = &storage[1..];
    assert_eq!(
        misaligned,
        payload.as_slice(),
        "offset slice must retain original payload bytes"
    );
    assert_ne!(
        misaligned.as_ptr() as usize % archived_payload_align::<AlignSensitive>(),
        0,
        "expected misaligned payload for test coverage"
    );
    let archived =
        archived_from_slice::<AlignSensitive>(misaligned).expect("realign archived payload");
    let _flags = DecodeFlagsGuard::enter(flags);
    let _payload = PayloadCtxGuard::enter(archived.bytes());
    let decoded = <AlignSensitive as DeserializePayload>::try_deserialize(archived.as_ref())
        .expect("decode misaligned AlignSensitive");
    assert_eq!(decoded, value);
    reset_decode_state();
}
#[test]
fn sequence_decoders_reject_zero_length_header_for_nonempty_element() {
    let original: Vec<(String, Vec<u8>)> = vec![("kind".to_owned(), vec![1, 2, 3, 4])];
    let framed = to_bytes(&original).expect("serialize vec");
    let flags = framed[Header::SIZE - 1];
    let mut payload = framed[Header::SIZE..].to_vec();
    let (len, seq_hdr) = {
        let _guard = DecodeFlagsGuard::enter(flags);
        read_seq_len_slice(&payload).expect("sequence header")
    };
    assert_eq!(len, original.len());
    let elem_hdr_len = {
        let _guard = DecodeFlagsGuard::enter(flags);
        let (_, hdr) = read_len_dyn_slice(&payload[seq_hdr..]).expect("element length header");
        hdr
    };
    assert!(
        seq_hdr + elem_hdr_len <= payload.len(),
        "element header extends beyond payload"
    );
    for byte in &mut payload[seq_hdr..seq_hdr + elem_hdr_len] {
        *byte = 0;
    }
    {
        let _guard = DecodeFlagsGuard::enter(flags);
        assert!(matches!(
            decode_field_canonical::<Vec<(String, Vec<u8>)>>(&payload),
            Err(Error::LengthMismatch)
        ));
        let mut decoded = Vec::new();
        assert!(matches!(
            decode_sequence_elements::<(String, Vec<u8>), _>(&payload, |value| {
                decoded.push(value);
                Ok(())
            }),
            Err(Error::LengthMismatch)
        ));
        assert!(decoded.is_empty(), "rejected elements must not be emitted");
    }
    reset_decode_state();
}
#[test]
fn payload_slice_from_ptr_cannot_escape_the_active_field() {
    reset_decode_state();
    let payload: Vec<u8> = (0..64).collect();
    set_decode_root(&payload);
    let ctx = &payload[8..24];
    let guard = PayloadCtxGuard::enter(ctx);
    let ptr = payload[48..].as_ptr();
    assert!(matches!(
        payload_slice_from_ptr(ptr),
        Err(Error::LengthMismatch)
    ));
    assert_eq!(payload_ctx_max_access().unwrap(), 0);
    drop(guard);
    clear_decode_root();
    reset_decode_state();
}
#[derive(Clone, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
#[norito(decode_from_slice)]
struct SignInProof {
    domain: String,
    uri: String,
    statement: String,
    issued_at: String,
    nonce: String,
}
#[test]
fn option_roundtrip_respects_compact_flags() {
    reset_decode_state();
    let payload: Option<SignInProof> = Some(SignInProof {
        domain: "example.org".into(),
        uri: "https://example.org/login".into(),
        statement: "Please sign in".into(),
        issued_at: "2025-01-01T00:00:00Z".into(),
        nonce: "abc123".into(),
    });
    let flags = header_flags::COMPACT_LEN;
    let encoded = {
        let _guard = DecodeFlagsGuard::enter(flags);
        let mut buf = Vec::new();
        serialize_to_buffer(&payload, &mut buf).expect("serialize option");
        buf
    };
    reset_decode_state();
    let decoded = {
        let _guard = DecodeFlagsGuard::enter(flags);
        let (decoded, used) = <Option<SignInProof> as DecodeFromSlice>::decode_from_slice(&encoded)
            .expect("decode option");
        assert_eq!(used, encoded.len());
        decoded
    };
    assert_eq!(decoded, payload);
}
#[test]
fn payload_without_padding_preserves_aligned_slice() {
    let payload = vec![0xAA, 0xBB, 0xCC, 0xDD];
    let view =
        payload_without_leading_padding(payload.as_slice(), payload.len(), 0).expect("aligned");
    assert_eq!(view, payload.as_slice());
}
#[test]
fn payload_without_padding_trims_alignment_prefix() {
    let padded = vec![0, 0, 0, 1, 2, 3, 4];
    let view =
        payload_without_leading_padding(&padded, 4, 3).expect("padding trimmed successfully");
    assert_eq!(view, &padded[3..]);
}
#[test]
fn payload_without_padding_rejects_nonzero_prefix() {
    let padded = vec![1, 0, 0, 1, 2, 3, 4];
    let err = payload_without_leading_padding(&padded, 4, 3)
        .expect_err("nonzero padding should be rejected");
    assert!(matches!(err, Error::LengthMismatch));
}
#[test]
fn payload_without_padding_exact_accepts_expected_padding() {
    let padded = vec![0, 0, 0xAA, 0xBB];
    let view =
        payload_without_leading_padding_exact(&padded, 2, 2).expect("exact padding should trim");
    assert_eq!(view, &padded[2..]);
}
#[test]
fn payload_without_padding_exact_rejects_nonzero_padding() {
    let padded = vec![1, 0, 0xAA, 0xBB];
    let err = payload_without_leading_padding_exact(&padded, 2, 2)
        .expect_err("nonzero padding should be rejected");
    assert!(matches!(err, Error::LengthMismatch));
}
#[test]
fn payload_without_padding_rejects_short_slice() {
    let data = vec![1, 2];
    let err = payload_without_leading_padding(&data, 3, 0).expect_err("length mismatch");
    matches!(err, Error::LengthMismatch);
}
#[test]
fn payload_without_padding_rejects_excess_prefix() {
    let payload = vec![9u8, 8, 7, 6];
    let padded = vec![0u8; 8];
    let mut with_prefix = Vec::new();
    with_prefix.extend_from_slice(&padded);
    with_prefix.extend_from_slice(&payload);
    let err = payload_without_leading_padding(&with_prefix, payload.len(), 4)
        .expect_err("excess padding should be rejected");
    assert!(matches!(err, Error::LengthMismatch));
}
#[test]
fn from_bytes_rejects_excess_padding() {
    let value: u64 = 0x1122_3344_5566_7788;
    let bytes = to_bytes(&value).expect("encode header-framed payload");
    let insert_at = Header::SIZE + payload_alignment_padding_for::<u64>();
    let mut mutated = Vec::with_capacity(bytes.len() + 2);
    mutated.extend_from_slice(&bytes[..insert_at]);
    mutated.extend_from_slice(&[0u8; 2]); // extra padding beyond alignment
    mutated.extend_from_slice(&bytes[insert_at..]);
    let result = from_bytes::<u64>(&mutated);
    assert!(matches!(result, Err(Error::LengthMismatch)));
}
#[test]
fn decode_from_bytes_rejects_excess_padding() {
    let value: u64 = 0x1122_3344_5566_7788;
    let bytes = to_bytes(&value).expect("encode header-framed payload");
    let insert_at = Header::SIZE + payload_alignment_padding_for::<u64>();
    let mut mutated = Vec::with_capacity(bytes.len() + 2);
    mutated.extend_from_slice(&bytes[..insert_at]);
    mutated.extend_from_slice(&[0u8; 2]); // extra padding beyond alignment
    mutated.extend_from_slice(&bytes[insert_at..]);
    let result = crate::decode_from_bytes::<u64>(&mutated);
    assert!(matches!(result, Err(Error::LengthMismatch)));
}
#[test]
fn from_bytes_rejects_trailing_bytes() {
    let value: u64 = 0xCAFEBABE_DEADBEEF;
    let mut bytes = to_bytes(&value).expect("encode header-framed payload");
    bytes.push(0);
    let result = from_bytes::<u64>(&bytes);
    assert!(matches!(result, Err(Error::LengthMismatch)));
}
#[test]
fn from_bytes_rejects_reserved_layout_flag() {
    reset_decode_state();
    let value: u64 = 0xABCD_EF01_2345_6789;
    let mut bytes = to_bytes(&value).expect("encode header-framed payload");
    bytes[Header::SIZE - 1] = 0x20;
    let result = from_bytes::<u64>(&bytes);
    assert!(matches!(
        result,
        Err(Error::UnsupportedFeature("layout flag"))
    ));
    reset_decode_state();
}
#[test]
fn from_compressed_bytes_rejects_trailing_bytes() {
    let value: u64 = 0x1111_2222_3333_4444;
    let mut bytes = to_bytes(&value).expect("encode header-framed payload");
    bytes.push(0);
    let result = from_compressed_bytes::<u64>(&bytes);
    assert!(matches!(result, Err(Error::LengthMismatch)));
}
#[cfg(feature = "compression")]
#[test]
fn from_compressed_bytes_rejects_trailing_compressed_bytes() {
    let value = vec![0u8; 64];
    let mut bytes =
        to_compressed_bytes(&value, Some(CompressionConfig::default())).expect("encode");
    bytes.extend_from_slice(&[0xAA, 0xBB]);
    let result = from_compressed_bytes::<Vec<u8>>(&bytes);
    assert!(matches!(result, Err(Error::LengthMismatch)));
}
#[test]
fn from_compressed_bytes_accepts_aligned_padding() {
    let value: u64 = 0xDEAD_BEEF_DEAD_BEEFu64;
    let bytes = to_compressed_bytes(&value, None).expect("encode compressed payload");
    let archived = from_compressed_bytes::<u64>(&bytes).expect("decode compressed payload");
    let decoded = u64::deserialize(&archived);
    assert_eq!(decoded, value);
}
#[cfg(feature = "compression")]
#[test]
fn from_compressed_bytes_rejects_length_mismatch() {
    let value = vec![0u8; 64];
    let mut bytes =
        to_compressed_bytes(&value, Some(CompressionConfig::default())).expect("encode");
    let len_offset = 4 + 1 + 1 + 16 + 1;
    let mut len_bytes = [0u8; 8];
    len_bytes.copy_from_slice(&bytes[len_offset..len_offset + 8]);
    let len = u64::from_le_bytes(len_bytes);
    let new_len = len.saturating_sub(1);
    bytes[len_offset..len_offset + 8].copy_from_slice(&new_len.to_le_bytes());
    let result = from_compressed_bytes::<Vec<u8>>(&bytes);
    assert!(matches!(result, Err(Error::LengthMismatch)));
}
#[allow(dead_code)]
#[repr(align(64))]
struct Align64(u8);
#[test]
fn archived_box_aligns_payload() {
    let archived = ArchivedBox::<Align64>::from_payload(vec![0xAA]);
    let ptr = archived.archived() as *const Archived<Align64> as usize;
    assert_eq!(ptr % archived_payload_align::<Align64>(), 0);
    assert_eq!(archived.bytes(), &[0xAA]);
}
#[test]
fn write_bare_frame_with_header_flags_matches_vec_framer() {
    reset_decode_state();
    let value = vec![9u32, 8, 7, 6];
    let (bare, flags) = crate::codec::encode_with_header_flags(&value);
    let expected =
        frame_bare_with_header_flags::<Vec<u32>>(&bare, flags).expect("frame payload into vec");
    let mut actual = Vec::new();
    write_bare_frame_with_header_flags::<Vec<u32>, _>(&mut actual, &bare, flags)
        .expect("frame payload into writer");
    assert_eq!(actual, expected);
}
#[test]
fn frame_current_payload_preserves_active_flags() {
    reset_decode_state();
    let value = vec![5u64, 6, 7, 8];
    let bytes = to_bytes(&value).expect("encode value");
    let original_flags = bytes[Header::SIZE - 1];
    let archived = from_bytes::<Vec<u64>>(&bytes).expect("decode header-framed payload");
    let _ = archived;
    let reframed =
        frame_current_payload_with_default_header::<Vec<u64>>().expect("reframe current payload");
    let mut cursor = std::io::Cursor::new(&reframed);
    let header = Header::read(&mut cursor).expect("read reframed header");
    assert_eq!(header.flags, original_flags);
    reset_decode_state();
}
#[test]
fn frame_current_payload_requires_negotiated_flags() {
    reset_decode_state();
    let bytes = vec![0u8; 8];
    let _ctx = PayloadCtxGuard::enter(&bytes);
    let err = frame_current_payload_with_default_header::<Vec<u8>>()
        .expect_err("payload context without flags should fail");
    matches!(err, Error::MissingLayoutFlags);
}
#[test]
fn encode_with_header_flags_exposes_explicit_layout() {
    reset_decode_state();
    let value = vec![5u64, 6, 7];
    let (bare, flags) = crate::codec::encode_with_header_flags(&value);
    let framed = frame_bare_with_header_flags::<Vec<u64>>(&bare, flags)
        .expect("frame payload with explicit flags");
    let mut cursor = std::io::Cursor::new(&framed);
    let header = Header::read(&mut cursor).expect("read header");
    assert_eq!(header.flags, flags);
}
#[test]
fn encode_with_header_flags_respects_decode_guard() {
    reset_decode_state();
    let _guard = DecodeFlagsGuard::enter(0);
    let value = vec![1u32, 2, 3, 4];
    let (_payload, flags) = crate::codec::encode_with_header_flags(&value);
    assert_eq!(flags, 0);
    reset_decode_state();
}
#[test]
fn read_len_readers_honor_compact_flags() {
    let flags = header_flags::COMPACT_LEN;
    let mut bytes = Vec::new();
    {
        let _guard = DecodeFlagsGuard::enter(flags);
        write_len_to_vec(&mut bytes, 3);
    }
    bytes.extend_from_slice(&[0xAA, 0xBB, 0xCC]);
    {
        let _guard = DecodeFlagsGuard::enter(flags);
        let (len_slice, hdr_slice) = read_len_dyn_slice(&bytes).expect("slice length header");
        assert_eq!(len_slice, 3);
        assert_eq!(hdr_slice, 1, "varint header should consume one byte");
        let _payload_guard = PayloadCtxGuard::enter(&bytes);
        let (len_ptr, hdr_ptr) =
            read_len_dyn_at_ptr(bytes.as_ptr()).expect("pointer length header");
        assert_eq!(len_ptr, 3);
        assert_eq!(hdr_ptr, 1);
    }
    // Sequence headers are fixed-width in v1.
    let mut seq_fixed = Vec::new();
    seq_fixed.extend_from_slice(&3u64.to_le_bytes());
    seq_fixed.extend_from_slice(&[0xAA, 0xBB, 0xCC]);
    for seq_flags in [0, header_flags::COMPACT_LEN] {
        let _guard = DecodeFlagsGuard::enter(seq_flags);
        let (seq_len_slice, seq_hdr_slice) =
            read_seq_len_slice(&seq_fixed).expect("sequence len slice");
        assert_eq!(seq_len_slice, 3);
        assert_eq!(seq_hdr_slice, 8);
        let _seq_payload = PayloadCtxGuard::enter(&seq_fixed);
        let (seq_len_ptr, seq_hdr_ptr) =
            unsafe { read_seq_len_ptr(seq_fixed.as_ptr()) }.expect("sequence len ptr");
        assert_eq!(seq_len_ptr, 3);
        assert_eq!(seq_hdr_ptr, 8);
    }
}
#[test]
fn decode_flags_guard_clears_state_between_payloads() {
    reset_decode_state();
    {
        let _compact = DecodeFlagsGuard::enter(header_flags::COMPACT_LEN);
        assert!(decode_flags_active());
        assert_eq!(get_decode_flags(), header_flags::COMPACT_LEN);
        assert!(use_compact_len());
    }
    assert!(!decode_flags_active());
    assert_eq!(get_decode_flags(), 0);
    assert!(
        use_compact_len(),
        "without an explicit guard, helpers use the V1 default layout"
    );
    {
        let _neutral = DecodeFlagsGuard::enter(0);
        assert!(decode_flags_active());
        assert_eq!(get_decode_flags(), 0);
        assert!(!use_compact_len());
    }
    reset_decode_state();
}
#[test]
fn decode_flags_guard_overrides_active_payload_context() {
    reset_decode_state();
    let payload = [0_u8; 8];
    let _ctx = PayloadCtxGuard::enter_with_flags(&payload, header_flags::COMPACT_LEN);
    assert_eq!(
        current_decode_flags_effective(),
        Some(header_flags::COMPACT_LEN)
    );
    {
        let _neutral = DecodeFlagsGuard::enter(0);
        assert_eq!(current_decode_flags_effective(), Some(0));
        assert!(!use_compact_len());
        let _nested = PayloadCtxGuard::enter(&payload);
        assert_eq!(current_decode_flags_effective(), Some(0));
        assert!(
            !use_compact_len(),
            "a nested payload must not restore stale outer layout flags"
        );
    }
    reset_decode_state();
}
#[derive(
    Debug,
    PartialEq,
    iroha_schema::IntoSchema,
    NoritoSerialize,
    NoritoDeserialize,
    crate::NoritoSchema,
)]
#[norito_schema(name = "norito.test.core.tests.StringAndNumber")]
struct StringAndNumber {
    first: String,
    second: u64,
}
#[test]
fn canonical_string_field_preserves_following_values() {
    let input = StringAndNumber {
        first: String::from("hello world"),
        second: 0xDEADBEEFCAFEBABE,
    };
    let bytes = crate::to_bytes(&input).expect("encode struct");
    let archived = crate::from_bytes::<StringAndNumber>(&bytes).expect("decode struct");
    let decoded = StringAndNumber::deserialize(archived);
    assert_eq!(decoded, input);
}
#[test]
fn archive_marker_accepts_short_valid_variable_payload() {
    let input = String::from("ok");
    let bytes = to_bytes(&input).expect("encode short string");
    let archived = from_bytes::<String>(&bytes).expect("validate short string frame");
    let decoded = String::try_deserialize(archived).expect("decode bounded short string payload");
    assert_eq!(decoded, input);
}
#[test]
fn archive_marker_defers_fixed_payload_bounds_to_fallible_decode() {
    let bytes = frame_bare_with_header_flags::<u64>(&[0_u8; 7], 0)
        .expect("frame deliberately truncated fixed payload");
    let archived =
        from_bytes::<u64>(&bytes).expect("frame validation must not reinterpret payload bytes");
    assert!(matches!(
        u64::try_deserialize(archived),
        Err(Error::LengthMismatch)
    ));
}
#[test]
fn primitive_roundtrip() {
    let value: u32 = 42;
    let bytes = to_bytes(&value).unwrap();
    let decoded: u32 = decode_from_bytes(&bytes).unwrap();
    assert_eq!(value, decoded);
}
#[test]
fn signed_primitive_roundtrip() {
    let value: i64 = -42;
    let bytes = to_bytes(&value).unwrap();
    let decoded: i64 = decode_from_bytes(&bytes).unwrap();
    assert_eq!(value, decoded);
}
#[test]
fn btreemap_entry_slices_returns_expected_windows() {
    let keys = [1u8, 2, 3, 4];
    let values = [10u8, 11, 12];
    let (key_slice, value_slice) =
        super::btreemap_entry_slices(&keys, &values, 1, 3, 0, 2, 0).expect("slices");
    assert_eq!(key_slice, &[2, 3]);
    assert_eq!(value_slice, &[10, 11]);
}
#[test]
fn btreemap_entry_slices_detects_out_of_bounds() {
    let keys = [1u8, 2];
    let values = [3u8, 4];
    let err = super::btreemap_entry_slices(&keys, &values, 0, 3, 0, 1, 0)
        .expect_err("slice bounds check");
    assert!(matches!(err, Error::LengthMismatch));
}
#[test]
fn collection_decoders_handle_u8_element_sequences_directly() {
    use std::collections::{BTreeSet, BinaryHeap, HashSet, LinkedList, VecDeque};
    reset_decode_state();
    let deque = VecDeque::from([1_u8, 2, 3]);
    let mut deque_bytes = Vec::new();
    serialize_to_buffer(&deque, &mut deque_bytes).expect("serialize vecdeque");
    assert!(
        deque_bytes.len() > 8 + deque.len(),
        "VecDeque<u8> uses per-element sequence framing"
    );
    let (decoded_deque, used) = <VecDeque<u8> as DecodeFromSlice>::decode_from_slice(&deque_bytes)
        .expect("decode vecdeque");
    assert_eq!(used, deque_bytes.len());
    assert_eq!(decoded_deque, deque);
    let list = LinkedList::from([4_u8, 5, 6]);
    let mut list_bytes = Vec::new();
    serialize_to_buffer(&list, &mut list_bytes).expect("serialize linked list");
    let (decoded_list, used) = <LinkedList<u8> as DecodeFromSlice>::decode_from_slice(&list_bytes)
        .expect("decode linked list");
    assert_eq!(used, list_bytes.len());
    assert_eq!(decoded_list, list);
    let heap = BinaryHeap::from([7_u8, 8, 9]);
    let mut heap_bytes = Vec::new();
    serialize_to_buffer(&heap, &mut heap_bytes).expect("serialize heap");
    let (decoded_heap, used) =
        <BinaryHeap<u8> as DecodeFromSlice>::decode_from_slice(&heap_bytes).expect("decode heap");
    assert_eq!(used, heap_bytes.len());
    assert_eq!(decoded_heap.into_sorted_vec(), heap.into_sorted_vec());
    let btree = BTreeSet::from([10_u8, 11, 12]);
    let mut btree_bytes = Vec::new();
    serialize_to_buffer(&btree, &mut btree_bytes).expect("serialize btree set");
    let (decoded_btree, used) = <BTreeSet<u8> as DecodeFromSlice>::decode_from_slice(&btree_bytes)
        .expect("decode btree set");
    assert_eq!(used, btree_bytes.len());
    assert_eq!(decoded_btree, btree);
    let hash = HashSet::from([13_u8, 14, 15]);
    let mut hash_bytes = Vec::new();
    serialize_to_buffer(&hash, &mut hash_bytes).expect("serialize hash set");
    let (decoded_hash, used) =
        <HashSet<u8> as DecodeFromSlice>::decode_from_slice(&hash_bytes).expect("decode hash set");
    assert_eq!(used, hash_bytes.len());
    assert_eq!(decoded_hash, hash);
    reset_decode_state();
}
#[test]
fn collection_and_map_encoded_lengths_match_payloads() {
    use std::collections::{
        BTreeMap, BTreeSet, BinaryHeap, HashMap, HashSet, LinkedList, VecDeque,
    };
    fn assert_lengths<T: NoritoSerialize>(value: &T) {
        let mut bytes = Vec::new();
        serialize_to_buffer(value, &mut bytes).expect("serialize value");
        assert_eq!(value.encoded_len_hint(), Some(bytes.len()));
        assert_eq!(value.encoded_len_exact(), Some(bytes.len()));
    }
    reset_decode_state();
    assert_lengths(&VecDeque::from([1_u16, 2, 3]));
    assert_lengths(&LinkedList::from([4_u16, 5, 6]));
    assert_lengths(&BinaryHeap::from([7_u16, 8, 9]));
    assert_lengths(&BTreeSet::from([10_u16, 11, 12]));
    assert_lengths(&HashSet::from([13_u16, 14, 15]));
    assert_lengths(&BTreeMap::from([(1_u16, 2_u32), (3, 4)]));
    assert_lengths(&HashMap::from([(5_u16, 6_u32), (7, 8)]));
    let _guard = DecodeFlagsGuard::enter(0);
    assert_lengths(&VecDeque::from([1_u16, 2, 3]));
    assert_lengths(&LinkedList::from([4_u16, 5, 6]));
    assert_lengths(&BinaryHeap::from([7_u16, 8, 9]));
    assert_lengths(&BTreeSet::from([10_u16, 11, 12]));
    assert_lengths(&HashSet::from([13_u16, 14, 15]));
    assert_lengths(&BTreeMap::from([(1_u16, 2_u32), (3, 4)]));
    assert_lengths(&HashMap::from([(5_u16, 6_u32), (7, 8)]));
    reset_decode_state();
}
#[test]
fn array_and_tuple_serialization_use_compact_element_lengths() {
    let _guard = DecodeFlagsGuard::enter(header_flags::COMPACT_LEN);
    let array = [5_u8, 7];
    let mut array_bytes = Vec::new();
    serialize_to_buffer(&array, &mut array_bytes).expect("serialize array");
    assert_eq!(array_bytes, [1, 5, 1, 7]);
    assert_eq!(array.encoded_len_hint(), Some(array_bytes.len()));
    assert_eq!(array.encoded_len_exact(), Some(array_bytes.len()));
    let mut tuple_bytes = Vec::new();
    let tuple = (5_u8, 7_u8);
    serialize_to_buffer(&tuple, &mut tuple_bytes).expect("serialize tuple");
    assert_eq!(tuple_bytes, [1, 5, 1, 7]);
    assert_eq!(tuple.encoded_len_hint(), Some(tuple_bytes.len()));
    assert_eq!(tuple.encoded_len_exact(), Some(tuple_bytes.len()));
    reset_decode_state();
}
#[test]
fn tuple_serialization_preserves_explicit_flags_in_nested_containers() {
    type NestedTuple = (Vec<Vec<u16>>, Vec<String>);

    fn serialize(value: &dyn SerializePayload) -> Vec<u8> {
        let mut bytes = Vec::new();
        serialize_to_buffer(value, &mut bytes).expect("serialize nested tuple fixture");
        bytes
    }

    let value: NestedTuple = (
        vec![vec![0x0102, 0x0304], vec![0x0506]],
        vec![String::from("alpha"), String::from("beta")],
    );

    reset_decode_state();
    let default_payload = serialize(&value);
    reset_decode_state();
    let explicit_default_payload = {
        let _guard = DecodeFlagsGuard::enter(default_encode_flags());
        serialize(&value)
    };
    assert_eq!(
        default_payload, explicit_default_payload,
        "an absent layout override must retain the canonical default bytes"
    );

    for flags in [0, header_flags::COMPACT_LEN] {
        reset_decode_state();
        let (tuple_payload, expected_payload) = {
            let _guard = DecodeFlagsGuard::enter(flags);
            assert_eq!(tuple_serialization_flags(), flags);

            let first = serialize(&value.0);
            let second = serialize(&value.1);
            let tuple_payload = serialize(&value);
            assert_eq!(value.encoded_len_hint(), Some(tuple_payload.len()));
            assert_eq!(value.encoded_len_exact(), Some(tuple_payload.len()));

            let mut expected = Vec::new();
            write_len_to_vec_with_flags(&mut expected, first.len() as u64, flags);
            expected.extend_from_slice(&first);
            write_len_to_vec_with_flags(&mut expected, second.len() as u64, flags);
            expected.extend_from_slice(&second);
            (tuple_payload, expected)
        };
        assert_eq!(
            tuple_payload, expected_payload,
            "tuple fields changed the explicit nested layout for flags 0x{flags:02x}"
        );

        let frame = frame_bare_with_header_flags::<NestedTuple>(&tuple_payload, flags)
            .expect("frame nested tuple with its explicit flags");
        let archived = from_bytes::<NestedTuple>(&frame)
            .expect("validate nested tuple frame with its explicit flags");
        let decoded = NestedTuple::try_deserialize(archived)
            .expect("decode nested tuple with its explicit flags");
        assert_eq!(decoded, value, "roundtrip changed flags 0x{flags:02x}");
    }
    reset_decode_state();
}
#[test]
fn string_and_result_lengths_match_compact_payloads() {
    use std::{borrow::Cow, rc::Rc, sync::Arc};
    let _guard = DecodeFlagsGuard::enter(header_flags::COMPACT_LEN);
    let value = String::from("ok");
    let mut string_bytes = Vec::new();
    serialize_to_buffer(&value, &mut string_bytes).expect("serialize string");
    assert_eq!(string_bytes, [2, b'o', b'k']);
    assert_eq!(value.encoded_len_hint(), Some(string_bytes.len()));
    assert_eq!(value.encoded_len_exact(), Some(string_bytes.len()));
    let borrowed = "ok";
    let mut borrowed_bytes = Vec::new();
    serialize_to_buffer(&borrowed, &mut borrowed_bytes).expect("serialize &str");
    assert_eq!(borrowed_bytes, string_bytes);
    assert_eq!(borrowed.encoded_len_hint(), Some(borrowed_bytes.len()));
    assert_eq!(borrowed.encoded_len_exact(), Some(borrowed_bytes.len()));
    let cow: Cow<'_, str> = Cow::Borrowed("ok");
    let mut cow_bytes = Vec::new();
    serialize_to_buffer(&cow, &mut cow_bytes).expect("serialize cow str");
    assert_eq!(cow_bytes, string_bytes);
    assert_eq!(cow.encoded_len_hint(), Some(cow_bytes.len()));
    assert_eq!(cow.encoded_len_exact(), Some(cow_bytes.len()));
    let boxed_str = String::from("ok").into_boxed_str();
    let mut boxed_str_bytes = Vec::new();
    serialize_to_buffer(&boxed_str, &mut boxed_str_bytes).expect("serialize box str");
    assert_eq!(boxed_str_bytes, string_bytes);
    assert_eq!(boxed_str.encoded_len_hint(), Some(boxed_str_bytes.len()));
    assert_eq!(boxed_str.encoded_len_exact(), Some(boxed_str_bytes.len()));
    let boxed = Box::new(String::from("ok"));
    let mut boxed_bytes = Vec::new();
    serialize_to_buffer(&boxed, &mut boxed_bytes).expect("serialize boxed string");
    assert_eq!(boxed_bytes, [3, 2, b'o', b'k']);
    assert_eq!(boxed.encoded_len_hint(), Some(boxed_bytes.len()));
    assert_eq!(boxed.encoded_len_exact(), Some(boxed_bytes.len()));
    let rc = Rc::new(String::from("ok"));
    let mut rc_bytes = Vec::new();
    serialize_to_buffer(&rc, &mut rc_bytes).expect("serialize rc string");
    assert_eq!(rc_bytes, boxed_bytes);
    assert_eq!(rc.encoded_len_hint(), Some(rc_bytes.len()));
    assert_eq!(rc.encoded_len_exact(), Some(rc_bytes.len()));
    let arc = Arc::new(String::from("ok"));
    let mut arc_bytes = Vec::new();
    serialize_to_buffer(&arc, &mut arc_bytes).expect("serialize arc string");
    assert_eq!(arc_bytes, boxed_bytes);
    assert_eq!(arc.encoded_len_hint(), Some(arc_bytes.len()));
    assert_eq!(arc.encoded_len_exact(), Some(arc_bytes.len()));
    let some = Some(String::from("ok"));
    let mut some_bytes = Vec::new();
    serialize_to_buffer(&some, &mut some_bytes).expect("serialize option some");
    assert_eq!(some_bytes, [1, 3, 2, b'o', b'k']);
    assert_eq!(some.encoded_len_hint(), Some(some_bytes.len()));
    assert_eq!(some.encoded_len_exact(), Some(some_bytes.len()));
    let none: Option<String> = None;
    let mut none_bytes = Vec::new();
    serialize_to_buffer(&none, &mut none_bytes).expect("serialize option none");
    assert_eq!(none_bytes, [0]);
    assert_eq!(none.encoded_len_hint(), Some(none_bytes.len()));
    assert_eq!(none.encoded_len_exact(), Some(none_bytes.len()));
    let ok: Result<String, String> = Ok(value);
    let mut ok_bytes = Vec::new();
    serialize_to_buffer(&ok, &mut ok_bytes).expect("serialize result ok");
    assert_eq!(ok_bytes, [0, 3, 2, b'o', b'k']);
    assert_eq!(ok.encoded_len_hint(), Some(ok_bytes.len()));
    assert_eq!(ok.encoded_len_exact(), Some(ok_bytes.len()));
    let err: Result<String, String> = Err(String::from("no"));
    let mut err_bytes = Vec::new();
    serialize_to_buffer(&err, &mut err_bytes).expect("serialize result err");
    assert_eq!(err_bytes, [1, 3, 2, b'n', b'o']);
    assert_eq!(err.encoded_len_hint(), Some(err_bytes.len()));
    assert_eq!(err.encoded_len_exact(), Some(err_bytes.len()));
    reset_decode_state();
}
#[test]
fn float_roundtrip() {
    let f32_val: f32 = 3.5;
    let bytes = to_bytes(&f32_val).unwrap();
    let decoded: f32 = decode_from_bytes(&bytes).unwrap();
    assert_eq!(f32_val, decoded);
    let f64_val: f64 = -2.25;
    let bytes = to_bytes(&f64_val).unwrap();
    let decoded: f64 = decode_from_bytes(&bytes).unwrap();
    assert_eq!(f64_val, decoded);
}
#[test]
fn string_roundtrip() {
    let value = String::from("norito");
    let bytes = to_bytes(&value).unwrap();
    let decoded: String = decode_from_bytes(&bytes).unwrap();
    assert_eq!(value, decoded);
}
#[test]
fn box_roundtrip() {
    let value: Box<u32> = Box::new(41);
    let bytes = to_bytes(&value).unwrap();
    let archived = from_bytes::<Box<u32>>(&bytes).unwrap();
    let decoded = <Box<u32> as DeserializePayload>::deserialize(archived);
    assert_eq!(value, decoded);
    let str_box: Box<String> = Box::new("boxed".into());
    let bytes = to_bytes(&str_box).unwrap();
    let archived = from_bytes::<Box<String>>(&bytes).unwrap();
    let decoded = <Box<String> as DeserializePayload>::deserialize(archived);
    assert_eq!(str_box, decoded);
}
#[test]
fn rc_roundtrip() {
    let value: Rc<u32> = Rc::new(7);
    let bytes = to_bytes(&value).unwrap();
    let archived = from_bytes::<Rc<u32>>(&bytes).unwrap();
    let decoded = <Rc<u32> as DeserializePayload>::deserialize(archived);
    assert_eq!(value, decoded);
    let str_rc: Rc<String> = Rc::new(String::from("shared"));
    let bytes = to_bytes(&str_rc).unwrap();
    let archived = from_bytes::<Rc<String>>(&bytes).unwrap();
    let decoded = <Rc<String> as DeserializePayload>::deserialize(archived);
    assert_eq!(str_rc, decoded);
}
#[test]
fn arc_roundtrip() {
    let value: Arc<u32> = Arc::new(99);
    let bytes = to_bytes(&value).unwrap();
    let archived = from_bytes::<Arc<u32>>(&bytes).unwrap();
    let decoded = <Arc<u32> as DeserializePayload>::deserialize(archived);
    assert_eq!(value, decoded);
    let str_arc: Arc<String> = Arc::new(String::from("threads"));
    let bytes = to_bytes(&str_arc).unwrap();
    let archived = from_bytes::<Arc<String>>(&bytes).unwrap();
    let decoded = <Arc<String> as DeserializePayload>::deserialize(archived);
    assert_eq!(str_arc, decoded);
}
#[test]
fn option_roundtrip() {
    let value = Some(5u32);
    let bytes = to_bytes(&value).unwrap();
    let decoded: Option<u32> = decode_from_bytes(&bytes).unwrap();
    assert_eq!(value, decoded);
    let none: Option<u32> = None;
    let bytes = to_bytes(&none).unwrap();
    let decoded: Option<u32> = decode_from_bytes(&bytes).unwrap();
    assert_eq!(none, decoded);
    let str_some: Option<String> = Some("abc".into());
    let bytes = to_bytes(&str_some).unwrap();
    let decoded: Option<String> = decode_from_bytes(&bytes).unwrap();
    assert_eq!(str_some, decoded);
    let str_none: Option<String> = None;
    let bytes = to_bytes(&str_none).unwrap();
    let decoded: Option<String> = decode_from_bytes(&bytes).unwrap();
    assert_eq!(str_none, decoded);
}
#[test]
fn vec_roundtrip() {
    let value = vec![1u32, 2, 3];
    let bytes = to_bytes(&value).unwrap();
    let decoded: Vec<u32> = decode_from_bytes(&bytes).unwrap();
    assert_eq!(value, decoded);
}
#[test]
fn decode_from_slice_vec_u32() {
    // Length-prefixed Vec<T> payload: [len:u64] then `[len][element]` per element.
    let elems = [1u32, 2, 3];
    for flags in [0, header_flags::COMPACT_LEN] {
        reset_decode_state();
        let _guard = DecodeFlagsGuard::enter(flags);
        let mut buf = Vec::new();
        buf.extend_from_slice(&(elems.len() as u64).to_le_bytes());
        for &e in &elems {
            let mut eb = Vec::new();
            serialize_to_buffer(&e, &mut eb).unwrap();
            write_len_to_vec_with_flags(&mut buf, eb.len() as u64, flags);
            buf.extend_from_slice(&eb);
        }
        let (out, used) = <Vec<u32> as DecodeFromSlice>::decode_from_slice(&buf).unwrap();
        assert_eq!(out, elems, "flags 0x{flags:02x}");
        assert_eq!(used, buf.len(), "flags 0x{flags:02x}");
    }
    reset_decode_state();
}
#[test]
fn vec_header_is_u64() {
    use crate::core::header_flags;
    let value = vec![42u8; 3];
    for flags in [0, header_flags::COMPACT_LEN] {
        reset_decode_state();
        let guard = DecodeFlagsGuard::enter(flags);
        let bytes = encode_adaptive(&value);
        drop(guard);
        assert!(bytes.len() >= 8);
        let mut hdr = [0u8; 8];
        hdr.copy_from_slice(&bytes[..8]);
        let reported = u64::from_le_bytes(hdr);
        assert_eq!(reported as usize, value.len(), "flags 0x{flags:02x}");
    }
    reset_decode_state();
}
#[test]
fn decode_from_slice_option_and_result() {
    // Use compact-len for these slice-based decodes since we encode lengths via `write_len`.
    set_decode_flags(header_flags::COMPACT_LEN);
    clear_payload_ctx();
    // Option::Some(String)
    let s = String::from("ok");
    let mut sbuf = Vec::new();
    serialize_to_buffer(&s, &mut sbuf).unwrap();
    let mut obuf = Vec::new();
    obuf.push(1u8); // tag
    crate::core::write_len(&mut obuf, sbuf.len() as u64).unwrap();
    obuf.extend_from_slice(&sbuf);
    let (oval, used) = <Option<String> as DecodeFromSlice>::decode_from_slice(&obuf).unwrap();
    assert_eq!(oval, Some(s));
    assert_eq!(used, obuf.len());
    // Result::Err(String)
    let e = String::from("err");
    let mut ebuf = Vec::new();
    serialize_to_buffer(&e, &mut ebuf).unwrap();
    let mut rbuf = Vec::new();
    rbuf.push(1u8); // Err tag
    crate::core::write_len(&mut rbuf, ebuf.len() as u64).unwrap();
    rbuf.extend_from_slice(&ebuf);
    let (rval, used) =
        <Result<String, String> as DecodeFromSlice>::decode_from_slice(&rbuf).unwrap();
    assert_eq!(rval, Err(String::from("err")));
    assert_eq!(used, rbuf.len());
    reset_decode_state();
}
#[test]
fn decode_from_slice_borrowed_bytes() {
    set_decode_flags(header_flags::COMPACT_LEN);
    let payload = b"bytes";
    let mut buf = Vec::new();
    crate::core::write_seq_len(&mut buf, payload.len() as u64).unwrap();
    buf.extend_from_slice(payload);
    let (out, used) = <&[u8] as DecodeFromSlice>::decode_from_slice(&buf).unwrap();
    assert_eq!(out, &payload[..]);
    assert_eq!(used, buf.len());
    reset_decode_state();
}
#[test]
fn vec_string_roundtrip() {
    let value = vec![String::from("foo"), String::from("bar")];
    let bytes = to_bytes(&value).unwrap();
    let decoded: Vec<String> = decode_from_bytes(&bytes).unwrap();
    assert_eq!(value, decoded);
}
#[test]
fn archived_cast_roundtrip() {
    #[repr(transparent)]
    struct Wrapper(Vec<u32>);
    let value = vec![1u32, 2, 3];
    let bytes = to_bytes(&value).unwrap();
    let archived_vec = from_bytes::<Vec<u32>>(&bytes).unwrap();
    let archived_wrapper: &Archived<Wrapper> = archived_vec.cast::<Wrapper>();
    let archived_vec_again: &Archived<Vec<u32>> = archived_wrapper.cast::<Vec<u32>>();
    let decoded = <Vec<u32> as DeserializePayload>::deserialize(archived_vec_again);
    assert_eq!(value, decoded);
}
#[test]
fn result_string_roundtrip() {
    let ok: Result<String, String> = Ok("ok".into());
    let bytes = to_bytes(&ok).unwrap();
    let decoded: Result<String, String> = decode_from_bytes(&bytes).unwrap();
    assert_eq!(ok, decoded);
    let err: Result<String, String> = Err("err".into());
    let bytes = to_bytes(&err).unwrap();
    let decoded: Result<String, String> = decode_from_bytes(&bytes).unwrap();
    assert_eq!(err, decoded);
}
#[test]
fn view_decode_string_and_vec() {
    let s = String::from("hello");
    let bytes = to_bytes(&s).unwrap();
    let view = from_bytes_view(&bytes).unwrap();
    let decoded: String = view.decode().unwrap();
    assert_eq!(decoded, s);
    let v = vec![1u32, 2, 3, 4];
    let bytes = to_bytes(&v).unwrap();
    let view = from_bytes_view(&bytes).unwrap();
    let decoded: Vec<u32> = view.decode().unwrap();
    assert_eq!(decoded, v);
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PayloadContextFingerprint {
    base: usize,
    len: usize,
    schema: Option<[u8; 16]>,
    max_access: usize,
    flags: u8,
    flags_active: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DecodeStateFingerprint {
    flags: u8,
    flags_active: bool,
    payload: Option<PayloadContextFingerprint>,
}
fn decode_state_fingerprint() -> DecodeStateFingerprint {
    DecodeStateFingerprint {
        flags: get_decode_flags(),
        flags_active: decode_flags_active(),
        payload: payload_ctx_state().map(|state| PayloadContextFingerprint {
            base: state.base,
            len: state.len,
            schema: state.schema,
            max_access: state.max_access,
            flags: state.flags,
            flags_active: state.flags_active,
        }),
    }
}
#[test]
fn archive_view_is_pure_and_scopes_custom_decode_state() {
    reset_decode_state();
    let outer_frame =
        frame_bare_with_header_flags::<u8>(&[0x31], 0).expect("frame outer scalar payload");
    let inner_flags = header_flags::COMPACT_LEN;
    let inner_frame = frame_bare_with_header_flags::<u8>(&[0x42], inner_flags)
        .expect("frame inner scalar payload");
    let ambient_payload = [0xA1, 0xA2, 0xA3];
    let ambient_schema = [0x5A; 16];
    let ambient_flags = default_encode_flags();
    let ambient_guard = PayloadCtxGuard::enter_with_schema_and_flags(
        &ambient_payload,
        ambient_schema,
        ambient_flags,
    );
    let ambient_state = decode_state_fingerprint();
    let outer = from_bytes_view(&outer_frame)
        .expect("view construction must ignore mismatched ambient layout state");
    assert_eq!(decode_state_fingerprint(), ambient_state);
    let inner = from_bytes_view(&inner_frame).expect("construct nested view");
    assert_eq!(decode_state_fingerprint(), ambient_state);
    let decoded = outer
        .decode_exact_with::<u8, u8, _>(|payload| {
            let state = payload_ctx_state().expect("view decode payload context");
            assert_eq!(state.schema, Some(outer.schema()));
            assert_eq!(state.flags, outer.flags());
            Ok((payload[0], payload.len()))
        })
        .expect("decode outer view");
    assert_eq!(decoded, 0x31);
    assert_eq!(decode_state_fingerprint(), ambient_state);
    let error = outer
        .decode_exact_with::<u8, u8, _>(|_| Err(Error::Message("expected failure".to_owned())))
        .expect_err("custom decoder error must propagate");
    assert!(matches!(error, Error::Message(_)));
    assert_eq!(decode_state_fingerprint(), ambient_state);
    let panic = std::panic::catch_unwind(|| {
        let _ = outer.decode_exact_with::<u8, u8, _>(|_| panic!("expected decoder panic"));
    });
    assert!(panic.is_err());
    assert_eq!(decode_state_fingerprint(), ambient_state);
    let nested = outer
        .decode_exact_with::<u8, u8, _>(|outer_payload| {
            let outer_state = decode_state_fingerprint();
            let inner_value = inner.decode_exact_with::<u8, u8, _>(|inner_payload| {
                let state = payload_ctx_state().expect("nested view payload context");
                assert_eq!(state.schema, Some(inner.schema()));
                assert_eq!(state.flags, inner_flags);
                Ok((inner_payload[0], inner_payload.len()))
            })?;
            assert_eq!(decode_state_fingerprint(), outer_state);
            Ok((outer_payload[0] ^ inner_value, outer_payload.len()))
        })
        .expect("decode nested views");
    assert_eq!(nested, 0x31 ^ 0x42);
    assert_eq!(decode_state_fingerprint(), ambient_state);
    let mut corrupted = outer_frame.clone();
    *corrupted.last_mut().expect("payload byte") ^= 0xFF;
    assert!(matches!(
        from_bytes_view(&corrupted),
        Err(Error::ChecksumMismatch)
    ));
    assert_eq!(decode_state_fingerprint(), ambient_state);
    drop(ambient_guard);
    reset_decode_state();
}
#[test]
fn archive_view_construction_does_not_influence_encoding() {
    reset_decode_state();
    let value = vec!["alpha".to_owned(), "beta".to_owned()];
    let canonical = to_bytes(&value).expect("encode canonical baseline");
    let alternate = {
        let _flags = DecodeFlagsGuard::enter(0);
        to_bytes(&value).expect("encode alternate layout")
    };
    assert_ne!(canonical, alternate, "fixture must distinguish layouts");
    let frame =
        frame_bare_with_header_flags::<u8>(&[7], 0).expect("frame non-default-layout scalar");
    let _view = from_bytes_view(&frame).expect("construct pure archive view");
    assert!(!decode_flags_active());
    assert!(payload_ctx_state().is_none());
    assert_eq!(
        to_bytes(&value).expect("encode after view construction"),
        canonical
    );
}
#[derive(Debug)]
struct DecodeBudgetProbe;
impl<'a> DecodeFromSlice<'a> for DecodeBudgetProbe {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), Error> {
        enforce_decode_sequence_length(u64::MAX)?;
        Ok((Self, bytes.len()))
    }
}
#[test]
fn archive_view_decode_installs_payload_derived_resource_limits() {
    let bytes = to_bytes(&0_u8).expect("encode a minimal archive");
    let view = from_bytes_view(&bytes).expect("validate archive framing");
    assert!(matches!(
        view.decode_unchecked::<DecodeBudgetProbe>(),
        Err(Error::SequenceLengthExceeded {
            length: u64::MAX,
            ..
        })
    ));
}
#[test]
fn archive_view_decoders_reject_a_zero_filled_logical_tail() {
    let value = 7_u8;
    let payload = [value, 0];
    let frame = frame_bare_with_header_flags::<u8>(&payload, V1_LAYOUT_FLAGS)
        .expect("frame scalar payload with a zero tail");
    let view = from_bytes_view(&frame).expect("validate tailed frame");
    assert!(matches!(view.decode::<u8>(), Err(Error::LengthMismatch)));
    assert!(matches!(
        view.decode_exact::<u8>(),
        Err(Error::LengthMismatch)
    ));
    assert!(matches!(
        view.decode_unchecked::<u8>(),
        Err(Error::LengthMismatch)
    ));
    assert!(matches!(
        decode_from_bytes::<u8>(&frame),
        Err(Error::LengthMismatch)
    ));
}

#[test]
fn archive_view_rejects_noncanonical_boolean_tags() {
    let frame = frame_bare_with_header_flags::<bool>(&[2], V1_LAYOUT_FLAGS)
        .expect("frame an invalid Boolean tag");
    let view = from_bytes_view(&frame).expect("validate the framed payload");
    assert!(matches!(
        view.decode::<bool>(),
        Err(Error::InvalidTag { .. })
    ));
    assert!(matches!(
        decode_from_bytes::<bool>(&frame),
        Err(Error::InvalidTag { .. })
    ));
}
#[test]
fn header_driven_compact_len_string_decode() {
    // Build a varint-length encoded string payload: len=3, data="abc"
    let mut payload = Vec::new();
    {
        let _guard = DecodeFlagsGuard::enter(header_flags::COMPACT_LEN);
        write_len_to_vec(&mut payload, 3);
    }
    payload.extend_from_slice(b"abc");
    // Compose header with COMPACT_LEN flag set
    let mut bytes = Vec::new();
    let mut header = Header::new(
        norito::schema::identity::frame_hash::<String>(),
        payload.len() as u64,
        crc64(&payload),
    );
    header.flags |= header_flags::COMPACT_LEN;
    header.write(&mut bytes).unwrap();
    bytes.extend_from_slice(&payload);
    let decoded: String = decode_from_bytes(&bytes).unwrap();
    assert_eq!(decoded, "abc");
}
#[test]
fn write_len_marks_compact_len_usage() {
    reset_decode_state();
    let encode_guard = EncodeContextGuard::enter();
    {
        let _guard = DecodeFlagsGuard::enter(header_flags::COMPACT_LEN);
        let mut buf = Vec::new();
        write_len_to_vec(&mut buf, 5);
        assert_eq!(buf, vec![5u8]);
    }
    assert!(
        compact_len_used(),
        "compact-len usage flag must be recorded"
    );
    drop(encode_guard);
    reset_decode_state();
}
#[test]
fn length_prefix_requires_compact_len_flag() {
    reset_decode_state();
    {
        let _guard = DecodeFlagsGuard::enter(0);
        let mut buf = Vec::new();
        write_len_to_vec(&mut buf, 5);
        assert_eq!(buf.len(), 8);
        let (len, used) = read_len_from_slice(&buf).expect("read len");
        assert_eq!(len, 5);
        assert_eq!(used, 8);
        assert_eq!(len_prefix_len(5), 8);
    }
    reset_decode_state();
}
#[test]
fn header_driven_fixed_len_string_decode() {
    // Build a fixed-u64 length encoded string payload with len=3
    let mut payload = Vec::new();
    payload.extend_from_slice(&(3u64.to_le_bytes()));
    payload.extend_from_slice(b"abc");
    // Compose header without COMPACT_LEN flag
    let mut bytes = Vec::new();
    let header = Header::new(
        norito::schema::identity::frame_hash::<String>(),
        payload.len() as u64,
        crc64(&payload),
    );
    header.write(&mut bytes).unwrap();
    bytes.extend_from_slice(&payload);
    let decoded: String = decode_from_bytes(&bytes).unwrap();
    assert_eq!(decoded, "abc");
}
#[test]
fn seq_len_respects_explicit_flags() {
    reset_decode_state();
    let guard = DecodeFlagsGuard::enter(0);
    let mut fixed_len_buf = Vec::new();
    fixed_len_buf.extend_from_slice(&(4u64.to_le_bytes()));
    let (len, used) = read_seq_len_slice(&fixed_len_buf).expect("fallback fixed len");
    assert_eq!(len, 4);
    assert_eq!(used, 8);
    drop(guard);
    reset_decode_state();
}
#[test]
fn strict_safe_read_len_and_decode_from_slice() {
    set_decode_flags(header_flags::COMPACT_LEN);
    let s = "hello-世界";
    let mut buf = Vec::new();
    crate::core::write_len(&mut buf, s.len() as u64).unwrap();
    buf.extend_from_slice(s.as_bytes());
    let (out_s, used) = String::decode_from_slice(&buf).unwrap();
    assert_eq!(out_s, s);
    assert_eq!(used, buf.len());
    let (out_str, used2) = <&str as DecodeFromSlice>::decode_from_slice(&buf).unwrap();
    assert_eq!(out_str, s);
    assert_eq!(used2, buf.len());
    reset_decode_state();
}
#[test]
fn fixed_u64_length_respects_usize_limits() {
    reset_decode_state();
    let _guard = DecodeFlagsGuard::enter(0);
    let overflow = (usize::MAX as u128)
        .checked_add(1)
        .and_then(|value| u64::try_from(value).ok());
    if let Some(len) = overflow {
        let buf = len.to_le_bytes();
        assert!(matches!(
            read_seq_len_slice(&buf),
            Err(Error::LengthMismatch)
        ));
        let result = unsafe { try_read_len_ptr_unchecked(buf.as_ptr()) };
        assert!(matches!(result, Err(Error::LengthMismatch)));
    } else {
        let len = 42u64;
        let buf = len.to_le_bytes();
        let (value, used) = read_seq_len_slice(&buf).expect("fixed len");
        assert_eq!(value, 42usize);
        assert_eq!(used, 8);
        let result = unsafe { try_read_len_ptr_unchecked(buf.as_ptr()) };
        let (value, used) = result.expect("fixed len ptr");
        assert_eq!(value, 42usize);
        assert_eq!(used, 8);
    }
}
#[test]
fn owned_payload_len_respects_usize_limits() {
    reset_decode_state();
    let guard = DecodeFlagsGuard::enter(0);
    let overflow = (usize::MAX as u128)
        .checked_add(1)
        .and_then(|value| u64::try_from(value).ok());
    if let Some(len) = overflow {
        let mut buf = Vec::new();
        buf.extend_from_slice(&len.to_le_bytes());
        let result = <Box<u8> as DecodeFromSlice>::decode_from_slice(&buf);
        assert!(matches!(result, Err(Error::LengthMismatch)));
    } else {
        let mut buf = Vec::new();
        buf.extend_from_slice(&1u64.to_le_bytes());
        buf.push(7);
        let (value, used) =
            <Box<u8> as DecodeFromSlice>::decode_from_slice(&buf).expect("decode box");
        assert_eq!(*value, 7);
        assert_eq!(used, buf.len());
    }
    drop(guard);
    reset_decode_state();
}
#[test]
fn decode_slice_usize_isize_respects_width() {
    let value = 17u64;
    let buf = value.to_le_bytes();
    let (out, used) = <usize as DecodeFromSlice>::decode_from_slice(&buf).expect("usize");
    assert_eq!(out, 17usize);
    assert_eq!(used, 8);
    let value = -9i64;
    let buf = value.to_le_bytes();
    let (out, used) = <isize as DecodeFromSlice>::decode_from_slice(&buf).expect("isize");
    assert_eq!(out, -9isize);
    assert_eq!(used, 8);
    let overflow = (usize::MAX as u128)
        .checked_add(1)
        .and_then(|value| u64::try_from(value).ok());
    if let Some(value) = overflow {
        let buf = value.to_le_bytes();
        let result = <usize as DecodeFromSlice>::decode_from_slice(&buf);
        assert!(matches!(result, Err(Error::LengthMismatch)));
        let value = i64::try_from(value).expect("overflow fits i64");
        let buf = value.to_le_bytes();
        let result = <isize as DecodeFromSlice>::decode_from_slice(&buf);
        assert!(matches!(result, Err(Error::LengthMismatch)));
    }
}
#[test]
fn vec_decode_rejects_impossible_header_sizes() {
    reset_decode_state();
    let _guard = DecodeFlagsGuard::enter(0);
    let len = usize::MAX / 8 + 1;
    let len_u64 = u64::try_from(len).expect("len fits u64");
    let mut buf = Vec::new();
    buf.extend_from_slice(&len_u64.to_le_bytes());
    let result = <Vec<u8> as DecodeFromSlice>::decode_from_slice(&buf);
    assert!(matches!(result, Err(Error::LengthMismatch)));
}
#[test]
fn vec_u8_encodes_as_len_plus_raw_bytes() {
    reset_decode_state();
    let value: Vec<u8> = (0..32).collect();
    let payload = encode_adaptive(&value);
    assert_eq!(payload.len(), 8 + value.len());
    let mut len_bytes = [0u8; 8];
    len_bytes.copy_from_slice(&payload[..8]);
    let len = u64::from_le_bytes(len_bytes) as usize;
    assert_eq!(len, value.len());
    assert_eq!(&payload[8..], value.as_slice());
    reset_decode_state();
}
#[test]
fn vec_u8_decode_rejects_len_prefixed_elements() {
    reset_decode_state();
    let guard = DecodeFlagsGuard::enter(0);
    let value: Vec<u8> = vec![1, 2, 3, 4];
    let mut payload = Vec::new();
    payload.extend_from_slice(&(value.len() as u64).to_le_bytes());
    for byte in &value {
        payload.extend_from_slice(&1u64.to_le_bytes());
        payload.push(*byte);
    }
    let result = decode_field_canonical::<Vec<u8>>(&payload);
    assert!(matches!(result, Err(Error::LengthMismatch)));
    drop(guard);
    reset_decode_state();
}
#[test]
fn encode_seq_payloads_counts_and_keeps_layout() {
    let items: Vec<Vec<u8>> = vec![vec![1, 2], vec![3], vec![4, 5, 6]];
    for flags in [0, header_flags::COMPACT_LEN] {
        let _guard = DecodeFlagsGuard::enter(flags);
        let mut out = Vec::new();
        let mut encoder = Encoder::for_buffer(&mut out);
        encode_seq_payloads::<Vec<u8>, _>(&mut encoder, items.iter())
            .expect("encode length-prefixed seq");
        let mut expected = (items.len() as u64).to_le_bytes().to_vec();
        for item in &items {
            let mut bytes = Vec::new();
            serialize_to_buffer(item, &mut bytes).expect("encode expected item");
            write_len_to_vec_with_flags(&mut expected, bytes.len() as u64, flags);
            expected.extend_from_slice(&bytes);
        }
        assert_eq!(out, expected, "flags {flags:#04x}");
    }
}
#[test]
fn encode_slice_payloads_matches_length_prefixed_layout() {
    let items = [0x0102_u16, 0x0304_u16, 0x0506_u16];
    for flags in [0, header_flags::COMPACT_LEN] {
        let _guard = DecodeFlagsGuard::enter(flags);
        let mut out = Vec::new();
        let mut encoder = Encoder::for_buffer(&mut out);
        encode_slice_payloads(&mut encoder, &items).expect("encode length-prefixed slice");
        let mut expected = 3_u64.to_le_bytes().to_vec();
        for item in items {
            write_len_to_vec_with_flags(&mut expected, 2, flags);
            expected.extend_from_slice(&item.to_le_bytes());
        }
        assert_eq!(out, expected, "flags {flags:#04x}");
    }
}
// Preserve pointer and length boundary coverage under `core::tests`.
include!("../core_payload_boundary_tests.rs");

#[test]
fn archive_custom_result_keeps_original_wire_identity_and_exact_consumption() {
    reset_decode_state();
    let frame = crate::encode_canonical(&0xA5_u128).unwrap();
    let view = from_bytes_view(&frame).unwrap();
    // This borrowed result deliberately has no codec; only u128 owns the frame identity.
    struct Borrowed<'a>(&'a [u8]);
    let borrowed = view
        .decode_exact_with::<u128, Borrowed<'_>, _>(|payload| {
            Ok((Borrowed(payload), payload.len()))
        })
        .unwrap();
    assert_eq!(borrowed.0, &0xA5_u128.to_le_bytes());
    assert!(core::ptr::eq(borrowed.0.as_ptr(), view.as_bytes().as_ptr()));
    let entered = std::cell::Cell::new(false);
    assert!(matches!(
        view.decode_exact_with::<u64, (), _>(|payload| {
            entered.set(true);
            Ok(((), payload.len()))
        }),
        Err(Error::SchemaMismatch)
    ));
    assert!(!entered.get());
    let padding = payload_alignment_padding_for::<u128>();
    if padding != 0 {
        let mut missing_padding = frame[..Header::SIZE].to_vec();
        missing_padding.extend_from_slice(&frame[Header::SIZE + padding..]);
        let view = from_bytes_view(&missing_padding).unwrap();
        assert!(matches!(
            view.decode_exact_with::<u128, (), _>(|payload| {
                entered.set(true);
                Ok(((), payload.len()))
            }),
            Err(Error::LengthMismatch)
        ));
        assert!(!entered.get());
    }
    let dropped = std::cell::Cell::new(false);
    struct Returned<'a>(&'a std::cell::Cell<bool>);
    impl Drop for Returned<'_> {
        fn drop(&mut self) {
            self.0.set(true);
        }
    }
    assert!(matches!(
        view.decode_exact_with::<u128, Returned<'_>, _>(|payload| {
            Ok((Returned(&dropped), payload.len() - 1))
        }),
        Err(Error::LengthMismatch)
    ));
    assert!(
        dropped.get(),
        "result ownership must be reclaimed on a consumption failure"
    );
    let mut unknown_flags = frame.clone();
    unknown_flags[Header::SIZE - 1] = 0x80;
    assert!(from_bytes_view(&unknown_flags).is_err());
    assert!(from_bytes_view(&frame[..frame.len() - 1]).is_err());
    let mut suffix = frame.clone();
    suffix.push(0);
    assert!(from_bytes_view(&suffix).is_err());
    reset_decode_state();
}

#[test]
fn archive_custom_result_cannot_widen_outer_element_or_allocation_budgets() {
    reset_decode_state();
    let frame = crate::encode_canonical(&0x42_u8).unwrap();
    let view = from_bytes_view(&frame).unwrap();
    let ambient = [0xA1, 0xA2];
    let guard = PayloadCtxGuard::enter_with_schema_and_flags(&ambient, [7; 16], 0);
    let original = decode_state_fingerprint();
    let allocation = with_decode_limits(DecodeLimits::new(32, 32, 32, 0, 8), || {
        view.decode_exact_with::<u8, bool, _>(|payload| {
            reserve_decode_allocation(1)?;
            Ok((true, payload.len()))
        })
    });
    assert!(matches!(
        allocation,
        Err(Error::TotalAllocationExceeded {
            attempted: 1,
            limit: 0
        })
    ));
    assert_eq!(decode_state_fingerprint(), original);
    let elements = with_decode_limits(DecodeLimits::new(1, 32, 1, 32, 8), || {
        view.decode_exact_with::<u8, bool, _>(|payload| {
            enforce_decode_sequence_length(2)?;
            Ok((true, payload.len()))
        })
    });
    assert!(matches!(
        elements,
        Err(Error::SequenceLengthExceeded {
            length: 2,
            limit: 1
        })
    ));
    assert_eq!(decode_state_fingerprint(), original);
    let (borrowed, usage) =
        with_decode_limits_measured(DecodeLimits::new(32, 32, 32, 0, 8), || {
            view.decode_exact_with::<u8, &[u8], _>(|payload| Ok((payload, payload.len())))
        });
    assert_eq!(borrowed.unwrap(), &[0x42]);
    assert_eq!(usage.total_allocated_bytes(), 0);
    assert_eq!(decode_state_fingerprint(), original);
    drop(guard);
    reset_decode_state();
}
