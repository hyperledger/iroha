// Included at crate scope to keep these focused codec regressions out of the parent file.
mod archive_slice_tests {
    use super::{ArchiveSlice, core};
    #[test]
    fn misaligned_slice_is_realigned() {
        let align = core::archived_payload_align::<[u64; 2]>();
        assert!(align > 1);
        let backing = vec![0u8; align * 2 + 1];
        let misaligned = &backing[1..1 + align * 2];
        let slice = ArchiveSlice::new(misaligned, align).expect("allocate slice");
        assert_eq!(slice.as_slice(), misaligned);
        assert_eq!(slice.as_slice().as_ptr() as usize % align, 0);
        assert!(slice.layout.is_some());
    }
    #[test]
    fn unit_alignment_is_noop() {
        let data = vec![1u8, 2, 3];
        let slice = ArchiveSlice::new(&data, 1).expect("allocate slice");
        assert_eq!(slice.as_slice(), &data[..]);
        assert!(slice.layout.is_none());
        assert_eq!(slice.ptr as *const u8, data.as_ptr());
    }
}
mod guarded_try_tests {
    use super::{Error, guarded_try_deserialize};
    #[test]
    fn panic_is_mapped_to_decode_error() {
        let result = guarded_try_deserialize::<(), _>(|| -> Result<(), Error> {
            panic!("forced panic for decode guard test");
        });
        assert!(matches!(result, Err(Error::DecodePanic { .. })));
    }
}
mod stream_map_iter_tests {
    use super::{Error, StreamMapIter, core};
    use std::{collections::HashMap, io::Cursor};
    fn frame_hashmap_payload(payload: &[u8], flags: u8) -> Vec<u8> {
        core::frame_bare_with_header_flags::<HashMap<u8, u8>>(payload, flags)
            .expect("frame payload")
    }
    #[test]
    fn stream_map_nonpacked_rejects_key_len_overflow() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&1u64.to_le_bytes());
        payload.extend_from_slice(&9u64.to_le_bytes());
        payload.extend_from_slice(&0u64.to_le_bytes());
        let bytes = frame_hashmap_payload(&payload, 0);
        let mut iter = StreamMapIter::<u8, u8>::new_hash(Cursor::new(bytes)).expect("iter");
        let item = iter.next().expect("item");
        assert!(matches!(item, Err(Error::LengthMismatch)));
    }
    #[test]
    fn stream_map_finish_empty_ok() {
        let payload = 0u64.to_le_bytes().to_vec();
        let bytes = frame_hashmap_payload(&payload, 0);
        let iter = StreamMapIter::<u8, u8>::new_hash(Cursor::new(bytes)).expect("iter");
        iter.finish().expect("finish");
    }
    #[test]
    fn stream_map_rejects_reserved_layout_flag_byte() {
        let payload = 0u64.to_le_bytes().to_vec();
        let mut bytes = frame_hashmap_payload(&payload, 0);
        assert_eq!(bytes[core::Header::SIZE - 1], 0, "header flags byte");
        bytes[core::Header::SIZE - 1] = 0x01;
        let result = StreamMapIter::<u8, u8>::new_hash(Cursor::new(bytes));
        assert!(matches!(
            result,
            Err(Error::UnsupportedFeature("layout flag"))
        ));
    }
}
mod json_string_allocation_tests {
    use super::{core, json};
    use json::JsonDeserialize as _;
    fn allocation_limits(bytes: usize) -> core::DecodeLimits {
        core::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, bytes, usize::MAX)
    }
    fn assert_string_allocation_is_exact(input: &str, expected: &str) {
        let (decoded, usage) =
            core::with_decode_limits_measured(allocation_limits(usize::MAX), || {
                json::Parser::new(input).parse_string()
            });
        let value = decoded.expect("JSON string fixture must decode");
        assert_eq!(value, expected);
        assert_eq!(usage.total_allocated_bytes(), value.capacity());
        let exact = usage.total_allocated_bytes();
        let (decoded, exact_usage) =
            core::with_decode_limits_measured(allocation_limits(exact), || {
                json::Parser::new(input).parse_string()
            });
        assert_eq!(
            decoded.expect("exact allocation budget must pass"),
            expected
        );
        assert_eq!(exact_usage.total_allocated_bytes(), exact);
        let (decoded, rejected_usage) =
            core::with_decode_limits_measured(allocation_limits(exact - 1), || {
                json::Parser::new(input).parse_string()
            });
        assert!(matches!(
            decoded,
            Err(json::Error::DecodeResource(
                crate::core::DecodeResourceError::TotalAllocationExceeded { .. }
            ))
        ));
        assert_eq!(
            rejected_usage.total_allocated_bytes(),
            0,
            "the exact destination is charged before allocation"
        );
    }
    #[test]
    fn unescaped_string_charges_retained_capacity_exactly() {
        assert_string_allocation_is_exact(r#""unescaped""#, "unescaped");
    }
    #[test]
    fn escaped_string_charges_retained_capacity_exactly() {
        assert_string_allocation_is_exact(r#""es\u0063aped""#, "escaped");
    }
    #[test]
    fn escaped_key_charges_retained_capacity_exactly() {
        let input = r#""es\u0063aped":0"#;
        let (decoded, usage) =
            core::with_decode_limits_measured(allocation_limits(usize::MAX), || {
                json::Parser::new(input).parse_key()
            });
        let key = decoded.expect("escaped key fixture must decode");
        let json::KeyRef::Owned(key) = key else {
            panic!("escaped key must own its decoded storage");
        };
        assert_eq!(key, "escaped");
        let exact = usage.total_allocated_bytes();
        assert_eq!(exact, key.capacity());
        let (decoded, exact_usage) =
            core::with_decode_limits_measured(allocation_limits(exact), || {
                json::Parser::new(input).parse_key()
            });
        assert_eq!(
            decoded.expect("exact key budget must pass").as_str(),
            "escaped"
        );
        assert_eq!(exact_usage.total_allocated_bytes(), exact);
        let (decoded, rejected_usage) =
            core::with_decode_limits_measured(allocation_limits(exact - 1), || {
                json::Parser::new(input).parse_key()
            });
        assert!(matches!(
            decoded,
            Err(json::Error::DecodeResource(
                crate::core::DecodeResourceError::TotalAllocationExceeded { .. }
            ))
        ));
        assert_eq!(rejected_usage.total_allocated_bytes(), 0);
    }
    #[test]
    fn value_copy_string_and_vec_charge_before_exact_allocation() {
        let string_source = json::Value::String("copied".to_owned());
        let (copied, usage) = core::with_decode_limits_measured(allocation_limits(6), || {
            String::json_from_value(&string_source)
        });
        assert_eq!(copied.expect("exact copied-string budget"), "copied");
        assert_eq!(usage.total_allocated_bytes(), 6);
        let (rejected, usage) = core::with_decode_limits_measured(allocation_limits(5), || {
            String::json_from_value(&string_source)
        });
        assert!(matches!(
            rejected,
            Err(json::Error::DecodeResource(
                crate::core::DecodeResourceError::TotalAllocationExceeded { .. }
            ))
        ));
        assert_eq!(usage.total_allocated_bytes(), 0);
        let vec_source = json::Value::Array(vec![
            json::Value::Bool(true),
            json::Value::Bool(false),
            json::Value::Bool(true),
        ]);
        let bytes = 3 * ::core::mem::size_of::<bool>();
        let (copied, usage) = core::with_decode_limits_measured(allocation_limits(bytes), || {
            Vec::<bool>::json_from_value(&vec_source)
        });
        assert_eq!(
            copied.expect("exact copied-vector budget"),
            [true, false, true]
        );
        assert_eq!(usage.total_allocated_bytes(), bytes);
        let (rejected, usage) =
            core::with_decode_limits_measured(allocation_limits(bytes - 1), || {
                Vec::<bool>::json_from_value(&vec_source)
            });
        assert!(matches!(
            rejected,
            Err(json::Error::DecodeResource(
                crate::core::DecodeResourceError::TotalAllocationExceeded { .. }
            ))
        ));
        assert_eq!(usage.total_allocated_bytes(), 0);
    }
}
