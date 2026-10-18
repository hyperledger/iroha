//! Block-framed one-byte elements must match the generic per-element codec exactly.

use super::*;

/// A one-byte payload without the `u8` byte-element hooks, so it takes the generic path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct GenericByte(u8);

impl SerializePayload for GenericByte {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        writer.write_all(&[self.0])?;
        Ok(())
    }
}

impl<'de> DeserializePayload<'de> for GenericByte {
    fn deserialize(archived: &'de Archived<Self>) -> Self {
        Self::try_deserialize(archived).expect("generic byte")
    }
    fn try_deserialize(archived: &'de Archived<Self>) -> Result<Self, Error> {
        try_read_archived_bytes::<_, 1>(archived).map(|[byte]| Self(byte))
    }
}

/// Element-framed sequence of borrowed elements, encoded through `write_element_sequence`.
struct ElementSequence<'a, T>(&'a [T]);

impl<T: SerializePayload> SerializePayload for ElementSequence<'_, T> {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        write_element_sequence::<T, _>(writer, self.0.iter())
    }
}

const LENGTHS: [usize; 11] = [0, 1, 2, 32, 64, 113, 114, 511, 513, 1952, 3309];

fn sample(len: usize) -> Vec<u8> {
    (0..len).map(|index| (index * 37 + 11) as u8).collect()
}

fn generic(bytes: &[u8]) -> Vec<GenericByte> {
    bytes.iter().copied().map(GenericByte).collect()
}

fn layouts() -> [u8; 2] {
    [0, header_flags::COMPACT_LEN]
}

/// Encode through every destination kind and return the shared bytes.
fn encode_everywhere(value: &dyn SerializePayload) -> Vec<u8> {
    let mut buffer = Vec::new();
    serialize_to_buffer(value, &mut buffer).expect("buffer destination");
    let mut writer = Vec::new();
    serialize_to_writer(value, &mut writer).expect("writer destination");
    assert_eq!(writer, buffer);
    let mut sink = ByteSink::with_headroom(0, 0);
    value
        .serialize(&mut Encoder::for_byte_sink(&mut sink))
        .expect("byte sink destination");
    assert_eq!(sink.into_inner(), buffer);
    assert_eq!(encoded_payload_len(value).expect("counting"), buffer.len());
    buffer
}

#[test]
fn byte_element_sequences_match_generic_framing_in_every_destination() {
    for flags in layouts() {
        let _flags = DecodeFlagsGuard::enter(flags);
        for len in LENGTHS {
            let bytes = sample(len);
            let wrapped = generic(&bytes);
            let fast = encode_everywhere(&ElementSequence(&bytes));
            let slow = encode_everywhere(&ElementSequence(&wrapped));
            assert_eq!(fast, slow, "flags {flags:#x}, len {len}");
            let stride = if flags == 0 { 9 } else { 2 };
            assert_eq!(fast.len(), 8 + len * stride);
            // Compact-length use is recorded exactly when an element prefix is emitted.
            let (_, fast_flags) = crate::codec::encode_with_header_flags(&ElementSequence(&bytes));
            let (_, slow_flags) =
                crate::codec::encode_with_header_flags(&ElementSequence(&wrapped));
            assert_eq!(fast_flags, slow_flags, "flags {flags:#x}, len {len}");
        }
    }
}

#[test]
fn byte_element_count_allowance_matches_generic_measurement() {
    for flags in layouts() {
        let _flags = DecodeFlagsGuard::enter(flags);
        for len in [0, 1, 2, 7, 600] {
            let bytes = sample(len);
            let wrapped = generic(&bytes);
            let exact = encoded_payload_len(&ElementSequence(&bytes)).unwrap();
            for maximum in [exact.saturating_sub(1), exact] {
                let fast = encoded_payload_len_bounded(&ElementSequence(&bytes), maximum);
                let slow = encoded_payload_len_bounded(&ElementSequence(&wrapped), maximum);
                assert_eq!(format!("{fast:?}"), format!("{slow:?}"), "len {len}");
            }
            // A real byte destination inside a bounded count charges each nested
            // one-byte element measurement, as the generic path does.
            let charged = |value: &dyn SerializePayload, maximum| {
                let guard = encode_writers::CountBudgetGuard::enter(maximum);
                let mut out = Vec::new();
                let written = serialize_to_buffer(value, &mut out).is_ok();
                written && guard.check().is_ok()
            };
            for maximum in [len.saturating_sub(1), len, len + 1] {
                assert_eq!(
                    charged(&ElementSequence(&bytes), maximum),
                    charged(&ElementSequence(&wrapped), maximum),
                    "len {len}, maximum {maximum}"
                );
            }
        }
    }
}

#[test]
fn byte_element_sequence_iterator_cardinality_errors_are_preserved() {
    struct Lying<'a>(&'a [u8], usize);
    impl Iterator for Lying<'_> {
        type Item = u8;
        fn next(&mut self) -> Option<u8> {
            let (first, rest) = self.0.split_first()?;
            self.0 = rest;
            Some(*first)
        }
    }
    impl ExactSizeIterator for Lying<'_> {
        fn len(&self) -> usize {
            self.1
        }
    }
    let bytes = sample(5);
    for reported in [4, 6] {
        let mut out = Vec::new();
        let result = write_element_sequence::<u8, _>(
            &mut Encoder::for_buffer(&mut out),
            Lying(&bytes, reported),
        );
        assert!(matches!(result, Err(Error::LengthMismatch)), "{reported}");
    }
}

macro_rules! byte_arrays {
    ($($len:literal),+ $(,)?) => {
        #[test]
        fn byte_element_arrays_match_generic_framing_and_decode_identically() {
            for flags in layouts() {
                let _flags = DecodeFlagsGuard::enter(flags);
                $({
                    let bytes: [u8; $len] = core::array::from_fn(|index| (index * 13 + 5) as u8);
                    let wrapped: [GenericByte; $len] = bytes.map(GenericByte);
                    let fast = encode_everywhere(&bytes);
                    let slow = encode_everywhere(&wrapped);
                    assert_eq!(fast, slow, "flags {flags:#x}, len {}", $len);
                    let mut tail = fast.clone();
                    tail.extend_from_slice(&[0xAA, 0x01]);
                    let decoded = decode_element_framed_byte_array::<$len>(&tail).unwrap();
                    assert_eq!(decoded, (bytes, fast.len()));
                    assert_eq!(
                        decoded,
                        decode_element_framed_byte_array_by_element::<$len>(&tail).unwrap()
                    );
                    assert_eq!(
                        decode_field_canonical::<[u8; $len]>(&fast).unwrap(),
                        (bytes, fast.len())
                    );
                    let zero = DecodeLimits::new(0, usize::MAX, 0, 0, 0);
                    let (result, usage) = with_decode_limits_measured(zero, || {
                        <[u8; $len] as DecodeFromSlice>::decode_from_slice(&fast)
                    });
                    assert_eq!(result.unwrap(), (bytes, fast.len()));
                    assert_eq!(usage.total_allocated_bytes(), 0);
                    // The per-element field ceiling is unchanged.
                    let narrow = DecodeLimits::new(usize::MAX, 0, usize::MAX, usize::MAX, 8);
                    let fast = with_decode_limits(narrow, || {
                        decode_element_framed_byte_array::<$len>(&fast)
                    });
                    let slow = with_decode_limits(narrow, || {
                        decode_element_framed_byte_array_by_element::<$len>(&tail)
                    });
                    assert_eq!(format!("{fast:?}"), format!("{slow:?}"));
                })+
            }
        }
    };
}
byte_arrays!(0, 1, 2, 32, 64, 1952, 3309);

/// Compare the canonical byte path with the generic per-element decoder.
fn assert_same_sequence_decode(bytes: &[u8], limits: DecodeLimits) {
    let (fast, fast_usage) = with_decode_limits_measured(limits, || {
        decode_element_sequence_from_slice_serial::<u8>(bytes)
    });
    let (slow, slow_usage) = with_decode_limits_measured(limits, || {
        decode_element_sequence_from_slice_serial::<GenericByte>(bytes).map(|(values, used)| {
            let values: Vec<u8> = values.into_iter().map(|value| value.0).collect();
            (values, used)
        })
    });
    assert_eq!(
        format!("{fast:?}"),
        format!("{slow:?}"),
        "input {bytes:02x?}, limits {limits:?}"
    );
    assert_eq!(
        fast_usage, slow_usage,
        "input {bytes:02x?}, limits {limits:?}"
    );
}

#[test]
fn byte_element_sequence_decode_matches_generic_values_errors_and_charges() {
    let unbounded = DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, 8);
    for flags in layouts() {
        let _flags = DecodeFlagsGuard::enter(flags);
        for len in LENGTHS {
            let bytes = sample(len);
            let mut encoded = Vec::new();
            serialize_to_buffer(&ElementSequence(&bytes), &mut encoded).unwrap();
            let (decoded, used) =
                decode_element_sequence_from_slice_serial::<u8>(&encoded).unwrap();
            assert_eq!((decoded, used), (bytes.clone(), encoded.len()));
            assert_same_sequence_decode(&encoded, unbounded);
            let mut tail = encoded.clone();
            tail.extend_from_slice(&[0x01, 0x02]);
            assert_same_sequence_decode(&tail, unbounded);
            let (_, usage) = with_decode_limits_measured(unbounded, || {
                decode_element_sequence_from_slice_serial::<u8>(&encoded)
            });
            // Every allocation ceiling around the measured charge reaches the same verdict,
            // including the reported refusal and partially charged counters.
            let charged = usage.total_allocated_bytes();
            for allocation in [
                0,
                len,
                charged.saturating_sub(len + 1),
                charged.saturating_sub(1),
                charged,
            ]
            .into_iter()
            .filter(|allocation| *allocation <= charged)
            {
                let limits = DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, allocation, 8);
                assert_same_sequence_decode(&encoded, limits);
            }
            for limits in [
                DecodeLimits::new(len.saturating_sub(1), usize::MAX, usize::MAX, usize::MAX, 8),
                DecodeLimits::new(usize::MAX, 0, usize::MAX, usize::MAX, 8),
                DecodeLimits::new(usize::MAX, usize::MAX, len.saturating_sub(1), usize::MAX, 8),
                DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, 0),
            ] {
                assert_same_sequence_decode(&encoded, limits);
            }
        }
    }
}

#[test]
fn byte_element_sequence_decode_preserves_every_malformed_rejection() {
    let unbounded = DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, 8);
    for flags in layouts() {
        let _flags = DecodeFlagsGuard::enter(flags);
        for len in [0, 1, 3] {
            let bytes = sample(len);
            let mut encoded = Vec::new();
            serialize_to_buffer(&ElementSequence(&bytes), &mut encoded).unwrap();
            for end in 0..encoded.len() {
                assert_same_sequence_decode(&encoded[..end], unbounded);
            }
            for index in 0..encoded.len() {
                for replacement in [0x00, 0x01, 0x02, 0x7f, 0x80, 0x81, 0xff] {
                    let mut changed = encoded.clone();
                    changed[index] = replacement;
                    assert_same_sequence_decode(&changed, unbounded);
                }
            }
        }
        // Overlong compact prefixes and wider elements stay generic rejections.
        let mut overlong = 1_u64.to_le_bytes().to_vec();
        overlong.extend_from_slice(&[0x81, 0x00, 0x05]);
        assert_same_sequence_decode(&overlong, unbounded);
        let mut wide = 1_u64.to_le_bytes().to_vec();
        write_len_to_vec_with_flags(&mut wide, 2, flags);
        wide.extend_from_slice(&[0x05, 0x06]);
        assert_same_sequence_decode(&wide, unbounded);
        let mut huge = u64::MAX.to_le_bytes().to_vec();
        huge.extend_from_slice(&[0x01, 0x05]);
        assert_same_sequence_decode(&huge, unbounded);
    }
}

#[test]
fn byte_element_array_decode_preserves_every_malformed_rejection() {
    for flags in layouts() {
        let _flags = DecodeFlagsGuard::enter(flags);
        let bytes: [u8; 3] = [0x10, 0x20, 0x30];
        let mut encoded = Vec::new();
        serialize_to_buffer(&bytes, &mut encoded).unwrap();
        let mut inputs = (0..encoded.len())
            .map(|end| encoded[..end].to_vec())
            .collect::<Vec<_>>();
        for index in 0..encoded.len() {
            for replacement in [0x00, 0x01, 0x02, 0x80, 0x81, 0xff] {
                let mut changed = encoded.clone();
                changed[index] = replacement;
                inputs.push(changed);
            }
        }
        for input in inputs {
            let fast = decode_element_framed_byte_array::<3>(&input);
            let slow = decode_element_framed_byte_array_by_element::<3>(&input);
            assert_eq!(
                format!("{fast:?}"),
                format!("{slow:?}"),
                "input {input:02x?}"
            );
        }
    }
}

#[test]
fn reserve_decode_allocation_units_matches_sequential_one_byte_charges() {
    for (outer, inner, units) in [(10, 4, 3), (10, 4, 5), (3, 10, 5), (5, 5, 5), (0, 9, 1)] {
        let measure = |batched: bool| {
            let outer_limits = DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, outer, 8);
            let inner_limits = DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, inner, 8);
            with_decode_limits_measured(outer_limits, || {
                let inner = with_decode_limits_measured(inner_limits, || {
                    if batched {
                        reserve_decode_allocation_units(units)
                    } else {
                        (0..units).try_for_each(|_| reserve_decode_allocation(1))
                    }
                });
                Ok::<_, Error>((format!("{:?}", inner.0), inner.1))
            })
        };
        let (batched, batched_outer) = measure(true);
        let (sequential, sequential_outer) = measure(false);
        assert_eq!(
            batched.unwrap(),
            sequential.unwrap(),
            "{outer} {inner} {units}"
        );
        assert_eq!(batched_outer, sequential_outer, "{outer} {inner} {units}");
    }
}
