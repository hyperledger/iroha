//! Original borrowed positional and optional framing with real storage charges.

use super::*;
use std::convert::Infallible;

fn inline_u16(field: CanonicalField<'_, u16>) -> Result<u16, DecodeIntoError<Infallible>> {
    field.with_payload(|bytes| {
        let (value, used) = <u16 as DecodeFromSlice>::decode_from_slice(bytes)?;
        if used != bytes.len() {
            return Err(Error::LengthMismatch.into());
        }
        Ok(value)
    })
}

#[test]
fn borrowed_positional_and_optional_fields_keep_original_bytes_and_zero_allocation_counters() {
    for flags in [0, header_flags::COMPACT_LEN] {
        let _flags = DecodeFlagsGuard::enter(flags);
        let value = 0x1234_u16;
        let mut framed = Vec::new();
        write_len_to_vec_with_flags(&mut framed, 2, flags);
        let prefix_len = framed.len();
        framed.extend_from_slice(&value.to_le_bytes());
        let limits = DecodeLimits::new(0, usize::MAX, 0, 0, 8);
        let (result, usage) = with_decode_limits_measured(limits, || {
            let _context = PayloadCtxGuard::enter(&framed);
            let mut offset = 0;
            let field = framed_field::<u16>(&framed, &mut offset)?;
            assert_eq!(offset, framed.len());
            assert_eq!(field.bytes().as_ptr(), framed[prefix_len..].as_ptr());
            assert_eq!(payload_ctx_max_access(), Some(prefix_len));
            inline_u16(field).map_err(DecodeIntoError::into_codec)
        });
        assert_eq!(result.unwrap(), value);
        assert_eq!(usage.total_elements(), 0);
        assert_eq!(usage.total_allocated_bytes(), 0);

        let mut some = vec![1];
        some.extend_from_slice(&framed);
        for (bytes, expected) in [(&some[..], Some(value)), (&[0][..], None)] {
            let (result, usage) = with_decode_limits_measured(limits, || {
                field_destination::canonical_field_from_slice::<Option<u16>>(bytes)
                    .decode_optional(inline_u16)
                    .map_err(DecodeIntoError::into_codec)
            });
            assert_eq!(result.unwrap(), expected);
            assert_eq!(usage.total_elements(), 0);
            assert_eq!(usage.total_allocated_bytes(), 0);
        }
    }
}

#[test]
fn borrowed_field_length_limit_keeps_precedence_over_bounds_and_allocation_budget() {
    for flags in [0, header_flags::COMPACT_LEN] {
        let _flags = DecodeFlagsGuard::enter(flags);
        let mut truncated = Vec::new();
        write_len_to_vec_with_flags(&mut truncated, 2, flags);
        // The declared body is absent. Its field ceiling still wins first,
        // while an admitted borrowed body reports the exact framing failure.
        let narrow = DecodeLimits::new(0, 1, 0, 0, 8);
        let (refused, usage) =
            with_decode_limits_measured(narrow, || take_length_prefixed_field(&truncated, 0));
        assert!(matches!(
            refused,
            Err(Error::FieldLengthExceeded {
                length: 2,
                limit: 1
            })
        ));
        assert_eq!(usage.total_allocated_bytes(), 0);
        let roomy = DecodeLimits::new(0, 2, 0, 0, 8);
        let (malformed, usage) =
            with_decode_limits_measured(roomy, || take_length_prefixed_field(&truncated, 0));
        assert!(matches!(malformed, Err(Error::LengthMismatch)));
        assert_eq!(usage.total_allocated_bytes(), 0);

        let mut optional = vec![1];
        optional.extend_from_slice(&truncated);
        let refused = with_decode_limits(narrow, || {
            prepared_option::option_payload_prefix(&optional, |tag| {
                Error::invalid_tag("Option::try_deserialize", tag)
            })
        });
        assert!(matches!(
            refused,
            Err(Error::FieldLengthExceeded {
                length: 2,
                limit: 1
            })
        ));
        let malformed = with_decode_limits(roomy, || {
            prepared_option::option_payload_prefix(&optional, |tag| {
                Error::invalid_tag("Option::try_deserialize", tag)
            })
        });
        assert!(matches!(malformed, Err(Error::LengthMismatch)));
    }
}

#[test]
fn borrowed_field_framing_preserves_real_alignment_and_owned_wrapper_charges() {
    for flags in [0, header_flags::COMPACT_LEN] {
        let _flags = DecodeFlagsGuard::enter(flags);
        let value = 0x0102_0304_0506_0708_u64;
        let mut framed = Vec::new();
        write_len_to_vec_with_flags(&mut framed, 8, flags);
        let prefix_len = framed.len();
        framed.extend_from_slice(&value.to_le_bytes());
        let alignment = archived_payload_align::<u64>();
        let mut original = vec![0xa5; framed.len() + alignment];
        let start = (0..alignment)
            .find(|start| (original.as_ptr() as usize + start + prefix_len) % alignment == 1)
            .unwrap();
        original[start..start + framed.len()].copy_from_slice(&framed);
        let bytes = &original[start..start + framed.len()];
        let zero = DecodeLimits::new(0, usize::MAX, 0, 0, 8);
        let refused = with_decode_limits(zero, || {
            let mut offset = 0;
            framed_field::<u64>(bytes, &mut offset)?.decode_owned()
        });
        assert!(matches!(
            refused,
            Err(Error::TotalAllocationExceeded {
                attempted: 8,
                limit: 0
            })
        ));
        let actual_copy = DecodeLimits::new(0, usize::MAX, 0, 8, 8);
        let (decoded, usage) = with_decode_limits_measured(actual_copy, || {
            let mut offset = 0;
            framed_field::<u64>(bytes, &mut offset)?.decode_owned()
        });
        assert_eq!(decoded.unwrap(), value);
        assert_eq!(usage.total_allocated_bytes(), 8);

        let mut wrapper = Vec::new();
        serialize_to_buffer(&Box::new(7_u8), &mut wrapper).unwrap();
        let mut outer = Vec::new();
        write_len_to_vec_with_flags(&mut outer, wrapper.len() as u64, flags);
        outer.extend_from_slice(&wrapper);
        let decode_wrapper = || {
            let mut offset = 0;
            framed_field::<Box<u8>>(&outer, &mut offset)?
                .with_payload::<Box<u8>, Infallible>(|bytes| {
                    let (value, used) = <Box<u8> as DecodeFromSlice>::decode_from_slice(bytes)?;
                    if used != bytes.len() {
                        return Err(Error::LengthMismatch.into());
                    }
                    Ok(value)
                })
                .map_err(DecodeIntoError::into_codec)
        };
        let wrapper_bytes = owned_box_allocation_bytes::<u8>();
        let refused = with_decode_limits(zero, decode_wrapper);
        assert!(matches!(
            refused,
            Err(Error::TotalAllocationExceeded { attempted, limit: 0 })
                if attempted == wrapper_bytes as u64
        ));
        let actual_wrapper = DecodeLimits::new(0, usize::MAX, 0, wrapper_bytes, 8);
        let (decoded, usage) = with_decode_limits_measured(actual_wrapper, decode_wrapper);
        assert_eq!(*decoded.unwrap(), 7);
        assert_eq!(usage.total_allocated_bytes(), wrapper_bytes);
    }
}

#[test]
fn framed_stack_byte_arrays_keep_original_source_and_errors_without_storage_charges() {
    let expected = [0x37_u8; 32];
    for flags in [0, header_flags::COMPACT_LEN] {
        let _flags = DecodeFlagsGuard::enter(flags);
        // Use the unchanged array serializer for its element-framed payload.
        let mut framed = Vec::new();
        serialize_to_buffer(&expected, &mut framed).unwrap();
        assert_ne!(framed.len(), expected.len());
        let zero = DecodeLimits::new(0, usize::MAX, 0, 0, 8);
        for (raw_field, payload) in [(false, &framed[..]), (true, &expected[..])] {
            for prefix in 0..16 {
                let mut original = vec![0xa5; prefix + payload.len()];
                original[prefix..].copy_from_slice(payload);
                let bytes = &original[prefix..];
                let pointer = bytes.as_ptr();
                let (decoded, usage) = with_decode_limits_measured(zero, || {
                    let _context = PayloadCtxGuard::enter(bytes);
                    let decoded = if raw_field {
                        // This test knows it supplied an explicit raw field; the generic
                        // array decoder never selects a layout from the input length.
                        let mut used = 0;
                        let decoded = decode_context_byte_array::<32>(pointer, &mut used)?;
                        finish_context_fields(pointer, used)?;
                        (decoded, used)
                    } else {
                        <[u8; 32] as DecodeFromSlice>::decode_from_slice(bytes)?
                    };
                    assert_eq!(payload_ctx(), Some((pointer as usize, bytes.len())));
                    assert_eq!(payload_ctx_max_access(), Some(bytes.len()));
                    Ok::<_, Error>(decoded)
                });
                assert_eq!(decoded.unwrap(), (expected, bytes.len()));
                assert_eq!(usage.total_elements(), 0);
                assert_eq!(usage.total_allocated_bytes(), 0);
                assert_eq!(bytes.as_ptr(), pointer);
                assert_eq!(bytes, payload);
            }
        }

        // A later malformed element keeps the declared field ceiling ahead
        // of its width and body checks, even after a valid borrowed element.
        let mut wrong_length = Vec::new();
        write_len_to_vec_with_flags(&mut wrong_length, 1, flags);
        wrong_length.push(expected[0]);
        write_len_to_vec_with_flags(&mut wrong_length, 2, flags);
        for field_limit in [1, 2] {
            let limits = DecodeLimits::new(0, field_limit, 0, 0, 8);
            let (decoded, usage) = with_decode_limits_measured(limits, || {
                <[u8; 32] as DecodeFromSlice>::decode_from_slice(&wrong_length)
            });
            if field_limit == 1 {
                assert!(matches!(
                    decoded,
                    Err(Error::FieldLengthExceeded {
                        length: 2,
                        limit: 1
                    })
                ));
            } else {
                assert!(matches!(decoded, Err(Error::LengthMismatch)));
            }
            assert_eq!(usage.total_elements(), 0);
            assert_eq!(usage.total_allocated_bytes(), 0);
        }

        let mut incomplete_prefix = Vec::new();
        write_len_to_vec_with_flags(&mut incomplete_prefix, 1, flags);
        incomplete_prefix.pop();
        for truncated in [&incomplete_prefix[..], &framed[..framed.len() - 1]] {
            let (decoded, usage) = with_decode_limits_measured(zero, || {
                <[u8; 32] as DecodeFromSlice>::decode_from_slice(truncated)
            });
            assert!(matches!(decoded, Err(Error::LengthMismatch)));
            assert_eq!(usage.total_elements(), 0);
            assert_eq!(usage.total_allocated_bytes(), 0);
        }
    }
}

#[test]
fn archived_fixed_array_charges_its_actual_element_copy_once_and_keeps_original_access() {
    let expected = [0x1234_u16];
    for flags in [0, header_flags::COMPACT_LEN] {
        let _flags = DecodeFlagsGuard::enter(flags);
        let mut framed = Vec::new();
        serialize_to_buffer(&expected, &mut framed).unwrap();
        let (_, prefix_len) = inspect_len_from_slice(&framed).unwrap();
        let alignment = archived_payload_align::<[u16; 1]>();
        let mut original = vec![0xa5; framed.len() + alignment];
        let start = (0..alignment)
            .find(|start| (original.as_ptr().addr() + start).is_multiple_of(alignment))
            .unwrap();
        original[start..start + framed.len()].copy_from_slice(&framed);
        let bytes = &original[start..start + framed.len()];
        let pointer = bytes.as_ptr();
        for allocation_limit in [1, 2] {
            let limits = DecodeLimits::new(0, usize::MAX, 0, allocation_limit, 8);
            let (decoded, usage) = with_decode_limits_measured(limits, || {
                let _context = PayloadCtxGuard::enter(bytes);
                let decoded = decode_field_canonical::<[u16; 1]>(bytes);
                assert_eq!(payload_ctx(), Some((pointer as usize, bytes.len())));
                assert_eq!(
                    payload_ctx_max_access(),
                    Some(if decoded.is_ok() {
                        bytes.len()
                    } else {
                        prefix_len
                    })
                );
                decoded
            });
            if allocation_limit == 1 {
                assert!(matches!(
                    decoded,
                    Err(Error::TotalAllocationExceeded {
                        attempted: 2,
                        limit: 1
                    })
                ));
                assert_eq!(usage.total_allocated_bytes(), 0);
            } else {
                assert_eq!(decoded.unwrap(), (expected, bytes.len()));
                assert_eq!(usage.total_allocated_bytes(), 2);
            }
            assert_eq!(usage.total_elements(), 0);
            assert_eq!(bytes.as_ptr(), pointer);
            assert_eq!(bytes, &framed);
        }

        let truncated = &bytes[..prefix_len];
        let limits = DecodeLimits::new(0, usize::MAX, 0, 0, 8);
        let (decoded, usage) =
            with_decode_limits_measured(limits, || decode_field_canonical::<[u16; 1]>(truncated));
        assert!(matches!(decoded, Err(Error::LengthMismatch)));
        assert_eq!(usage.total_allocated_bytes(), 0);
        assert_eq!(usage.total_elements(), 0);
    }
}

#[test]
fn generic_byte_arrays_reject_length_n_truncation_inside_and_outside_options() {
    let expected = [5_u8, 7];
    for flags in [0, header_flags::COMPACT_LEN] {
        let _flags = DecodeFlagsGuard::enter(flags);
        let mut framed = Vec::new();
        serialize_to_buffer(&expected, &mut framed).unwrap();
        let truncated = &framed[..expected.len()];
        let zero = DecodeLimits::new(0, usize::MAX, 0, 0, 8);
        let (valid, usage) =
            with_decode_limits_measured(zero, || decode_field_canonical::<[u8; 2]>(&framed));
        assert_eq!(valid.unwrap(), (expected, framed.len()));
        assert_eq!(usage.total_allocated_bytes(), 0);
        assert_eq!(usage.total_elements(), 0);

        for decoded in [
            with_decode_limits(zero, || {
                <[u8; 2] as DecodeFromSlice>::decode_from_slice(truncated)
            }),
            with_decode_limits(zero, || decode_field_canonical::<[u8; 2]>(truncated)),
        ] {
            assert!(matches!(decoded, Err(Error::LengthMismatch)));
        }
        let mut optional = vec![1];
        write_len_to_vec_with_flags(&mut optional, truncated.len() as u64, flags);
        optional.extend_from_slice(truncated);
        for decoded in [
            with_decode_limits(zero, || {
                <Option<[u8; 2]> as DecodeFromSlice>::decode_from_slice(&optional)
            }),
            with_decode_limits(zero, || {
                decode_field_canonical::<Option<[u8; 2]>>(&optional)
            }),
        ] {
            assert!(matches!(decoded, Err(Error::LengthMismatch)));
        }
        let mut valid_optional = vec![1];
        write_len_to_vec_with_flags(&mut valid_optional, framed.len() as u64, flags);
        valid_optional.extend_from_slice(&framed);
        assert_eq!(
            with_decode_limits(zero, || {
                decode_field_canonical::<Option<[u8; 2]>>(&valid_optional)
            })
            .unwrap(),
            (Some(expected), valid_optional.len())
        );
    }
}

#[test]
fn archived_and_slice_fixed_arrays_reject_an_overwide_element_with_its_actual_copy_charge() {
    for flags in [0, header_flags::COMPACT_LEN] {
        let _flags = DecodeFlagsGuard::enter(flags);
        let mut framed = Vec::new();
        write_len_to_vec_with_flags(&mut framed, 3, flags);
        framed.extend_from_slice(&0x1234_u16.to_le_bytes());
        framed.push(0xaa);
        let alignment = archived_payload_align::<[u16; 1]>();
        let mut original = vec![0xa5; framed.len() + alignment];
        let start = (0..alignment)
            .find(|start| (original.as_ptr().addr() + start).is_multiple_of(alignment))
            .unwrap();
        original[start..start + framed.len()].copy_from_slice(&framed);
        let bytes = &original[start..start + framed.len()];
        let limits = DecodeLimits::new(0, usize::MAX, 0, usize::MAX, 8);
        let (slice, slice_usage) = with_decode_limits_measured(limits, || {
            <[u16; 1] as DecodeFromSlice>::decode_from_slice(bytes)
        });
        assert!(matches!(slice, Err(Error::LengthMismatch)));
        assert_eq!(slice_usage.total_allocated_bytes(), 0);
        let (owned, owned_usage) = with_decode_limits_measured(limits, || {
            let _context = PayloadCtxGuard::enter(bytes);
            let decoded = decode_field_canonical::<[u16; 1]>(bytes);
            assert_eq!(payload_ctx(), Some((bytes.as_ptr() as usize, bytes.len())));
            assert_eq!(payload_ctx_max_access(), Some(bytes.len()));
            decoded
        });
        assert!(matches!(owned, Err(Error::LengthMismatch)));
        assert_eq!(owned_usage.total_allocated_bytes(), 3);
        assert_eq!(owned_usage.total_elements(), 0);
        assert_eq!(bytes, &framed);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct UntrackedArrayByte(u8);

impl SerializePayload for UntrackedArrayByte {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        writer.write_all(&[self.0])?;
        Ok(())
    }
}

impl<'de> DeserializePayload<'de> for UntrackedArrayByte {
    fn deserialize(archived: &'de Archived<Self>) -> Self {
        Self::try_deserialize(archived).unwrap()
    }

    fn try_deserialize(archived: &'de Archived<Self>) -> Result<Self, Error> {
        // Deliberately exercise the supported untracked custom-decoder contract.
        let bytes = payload_slice_from_ptr(core::ptr::from_ref(archived).cast::<u8>())?;
        let byte = *bytes.first().ok_or(Error::LengthMismatch)?;
        if byte == 0xfe {
            return Err(Error::InvalidValue {
                context: "untracked array byte",
            });
        }
        Ok(Self(byte & 0x7f))
    }
}

#[test]
fn archived_fixed_arrays_validate_untracked_custom_elements_against_original_canonical_bytes() {
    for flags in [0, header_flags::COMPACT_LEN] {
        let _flags = DecodeFlagsGuard::enter(flags);
        for body in [&[7_u8][..], &[7, 8][..], &[0x87][..], &[0xfe][..]] {
            let mut framed = Vec::new();
            write_len_to_vec_with_flags(&mut framed, body.len() as u64, flags);
            framed.extend_from_slice(body);
            let limits = DecodeLimits::new(0, usize::MAX, 0, usize::MAX, 8);
            let (decoded, usage) = with_decode_limits_measured(limits, || {
                let _context = PayloadCtxGuard::enter(&framed);
                let decoded = decode_field_canonical::<[UntrackedArrayByte; 1]>(&framed);
                assert_eq!(
                    payload_ctx(),
                    Some((framed.as_ptr() as usize, framed.len()))
                );
                assert_eq!(payload_ctx_max_access(), Some(framed.len()));
                decoded
            });
            match body {
                [7] => assert_eq!(decoded.unwrap(), ([UntrackedArrayByte(7)], framed.len())),
                [0xfe] => assert!(matches!(
                    decoded,
                    Err(Error::InvalidValue {
                        context: "untracked array byte"
                    })
                )),
                _ => assert!(matches!(decoded, Err(Error::LengthMismatch))),
            }
            assert_eq!(usage.total_allocated_bytes(), body.len());
            assert_eq!(usage.total_elements(), 0);
            assert_eq!(&framed[framed.len() - body.len()..], body);
        }
    }
}

#[test]
fn archived_fixed_array_canonical_refusal_drops_current_and_completed_elements() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static DROPS: AtomicUsize = AtomicUsize::new(0);
    struct DropByte(u8);
    impl Drop for DropByte {
        fn drop(&mut self) {
            DROPS.fetch_add(1, Ordering::Relaxed);
        }
    }
    impl SerializePayload for DropByte {
        fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
            writer.write_all(&[self.0])?;
            Ok(())
        }
    }
    impl<'de> DeserializePayload<'de> for DropByte {
        fn deserialize(archived: &'de Archived<Self>) -> Self {
            Self::try_deserialize(archived).unwrap()
        }
        fn try_deserialize(archived: &'de Archived<Self>) -> Result<Self, Error> {
            let bytes = payload_slice_from_ptr(core::ptr::from_ref(archived).cast::<u8>())?;
            let byte = *bytes.first().ok_or(Error::LengthMismatch)?;
            Ok(Self(byte & 0x7f))
        }
    }
    for flags in [0, header_flags::COMPACT_LEN] {
        let _flags = DecodeFlagsGuard::enter(flags);
        let mut framed = Vec::new();
        for byte in [7_u8, 11, 0x87] {
            write_len_to_vec_with_flags(&mut framed, 1, flags);
            framed.push(byte);
        }
        DROPS.store(0, Ordering::Relaxed);
        let limits = DecodeLimits::new(0, usize::MAX, 0, usize::MAX, 8);
        let (decoded, usage) = with_decode_limits_measured(limits, || {
            decode_field_canonical::<[DropByte; 3]>(&framed)
        });
        assert!(matches!(decoded, Err(Error::LengthMismatch)));
        assert_eq!(DROPS.load(Ordering::Relaxed), 3);
        assert_eq!(usage.total_allocated_bytes(), 3);
        assert_eq!(usage.total_elements(), 0);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct UntrackedArrayUnit;

impl SerializePayload for UntrackedArrayUnit {
    fn serialize(&self, _writer: &mut Encoder<'_>) -> Result<(), Error> {
        Ok(())
    }
}

impl<'de> DeserializePayload<'de> for UntrackedArrayUnit {
    fn deserialize(_archived: &'de Archived<Self>) -> Self {
        Self
    }
}

#[test]
fn archived_fixed_arrays_preserve_zero_sized_untracked_elements_without_storage_charges() {
    let expected = [UntrackedArrayUnit; 2];
    for flags in [0, header_flags::COMPACT_LEN] {
        let _flags = DecodeFlagsGuard::enter(flags);
        let mut framed = Vec::new();
        serialize_to_buffer(&expected, &mut framed).unwrap();
        let zero = DecodeLimits::new(0, usize::MAX, 0, 0, 8);
        let (decoded, usage) = with_decode_limits_measured(zero, || {
            let _context = PayloadCtxGuard::enter(&framed);
            let decoded = decode_field_canonical::<[UntrackedArrayUnit; 2]>(&framed)?;
            assert_eq!(payload_ctx_max_access(), Some(framed.len()));
            Ok::<_, Error>(decoded)
        });
        assert_eq!(decoded.unwrap(), (expected, framed.len()));
        assert_eq!(usage.total_allocated_bytes(), 0);
        assert_eq!(usage.total_elements(), 0);
    }
}

#[test]
fn archived_fixed_array_markers_outside_original_context_refuse_before_access_or_allocation() {
    for flags in [0, header_flags::COMPACT_LEN] {
        let _flags = DecodeFlagsGuard::enter(flags);
        let mut framed = Vec::new();
        serialize_to_buffer(&[0x1234_u16], &mut framed).unwrap();
        let mut backing = [0xa5_u8; 64];
        let start = 8;
        let end = start + framed.len();
        backing[start..end].copy_from_slice(&framed);
        let payload = &backing[start..end];
        let original_root = payload_root_span();
        for marker_offset in [0, end + 1] {
            // SAFETY: this non-null address stays in the live backing buffer.
            // Archived is a zero-sized byte-aligned marker; its payload bytes
            // deliberately lie outside the narrower active context.
            let archived = unsafe {
                &*backing
                    .as_ptr()
                    .add(marker_offset)
                    .cast::<Archived<[u16; 1]>>()
            };
            let zero = DecodeLimits::new(0, usize::MAX, 0, 0, 8);
            let (decoded, usage) = with_decode_limits_measured(zero, || {
                let _context = PayloadCtxGuard::enter(payload);
                let decoded = <[u16; 1] as DeserializePayload>::try_deserialize(archived);
                assert_eq!(
                    payload_ctx(),
                    Some((payload.as_ptr() as usize, payload.len()))
                );
                assert_eq!(payload_ctx_max_access(), Some(0));
                assert_eq!(payload_root_span(), original_root);
                decoded
            });
            assert!(matches!(decoded, Err(Error::LengthMismatch)));
            assert_eq!(usage.total_allocated_bytes(), 0);
            assert_eq!(usage.total_elements(), 0);
            assert_eq!(payload, &framed);
        }
    }
}
