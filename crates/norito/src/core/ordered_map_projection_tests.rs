//! Borrowed canonical maps preserve byte identity and checked-output failure semantics.

use super::*;

struct Map<'a>(&'a [(u16, u32)], usize);
impl SerializePayload for Map<'_> {
    fn serialize(&self, out: &mut Encoder<'_>) -> Result<(), Error> {
        write_ordered_map_entries(out, self.1, self.0.iter().map(|(key, value)| (key, value)))
    }
}

#[test]
fn borrowed_ordered_map_matches_canonical_btree_layout() {
    let entries = [(1_u16, 3_u32), (256, 65537), (u16::MAX, u32::MAX)];
    let expected: BTreeMap<_, _> = entries.into_iter().collect();
    for flags in [0, header_flags::COMPACT_LEN] {
        let _guard = DecodeFlagsGuard::enter(flags);
        for count in [0, entries.len()] {
            let map = Map(&entries[..count], count);
            let mut actual = Vec::new();
            serialize_to_buffer(&map, &mut actual).unwrap();
            assert_eq!(encoded_payload_len(&map).unwrap(), actual.len());
            let mut reference = Vec::new();
            if count == 0 {
                serialize_to_buffer(&BTreeMap::<u16, u32>::new(), &mut reference).unwrap();
            } else {
                serialize_to_buffer(&expected, &mut reference).unwrap();
            }
            assert_eq!(actual, reference);
            let (decoded, consumed) =
                <BTreeMap<u16, u32> as DecodeFromSlice>::decode_from_slice(&actual).unwrap();
            assert_eq!(consumed, actual.len());
            assert_eq!(decoded.len(), count);
            if count != 0 {
                assert_eq!(decoded, expected);
            }
        }
    }
}

#[test]
fn borrowed_ordered_map_rejects_duplicate_order_and_cardinality_in_both_destinations() {
    let ascending = [(1, 2), (3, 4)];
    let duplicate = [(1, 2), (1, 3)];
    let descending = [(2, 3), (1, 4)];
    for flags in [0, header_flags::COMPACT_LEN] {
        let _guard = DecodeFlagsGuard::enter(flags);
        for (entries, count) in [
            (&ascending[..], 1),
            (&ascending[..], 3),
            (&duplicate[..], 2),
            (&descending[..], 2),
        ] {
            let map = Map(entries, count);
            assert!(matches!(
                encoded_payload_len(&map),
                Err(Error::LengthMismatch)
            ));
            assert!(matches!(
                serialize_to_buffer(&map, &mut Vec::new()),
                Err(Error::LengthMismatch)
            ));
        }
    }
}

#[test]
fn borrowed_ordered_map_preserves_measurement_and_destination_errors() {
    struct Refused;
    impl SerializePayload for Refused {
        fn serialize(&self, _out: &mut Encoder<'_>) -> Result<(), Error> {
            Err(Error::AllocationFailed { bytes: 73 })
        }
    }
    struct MapWithRefusal;
    impl SerializePayload for MapWithRefusal {
        fn serialize(&self, out: &mut Encoder<'_>) -> Result<(), Error> {
            write_ordered_map_entries(out, 1, [(&1_u8, &Refused)])
        }
    }
    assert!(matches!(
        encoded_payload_len(&MapWithRefusal),
        Err(Error::AllocationFailed { bytes: 73 })
    ));
    assert!(matches!(
        serialize_to_buffer(&MapWithRefusal, &mut Vec::new()),
        Err(Error::AllocationFailed { bytes: 73 })
    ));
    struct RejectOutput;
    impl std::io::Write for RejectOutput {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "original destination refusal",
            ))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut sink = RejectOutput;
    let result = Map(&[(1, 2)], 1).serialize(&mut Encoder::new(&mut sink));
    assert!(result.is_err());
}
