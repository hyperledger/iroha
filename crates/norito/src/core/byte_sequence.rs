//! Advertised element-sequence traversal with caller-owned byte destinations.

use super::*;

/// Decode a byte element sequence into an already owned destination prefix.
///
/// This uses the same advertised element framing as `ConstVec<u8>`, not
/// `Vec<u8>`'s raw-byte specialization. V1 admits fixed or compact per-element
/// length prefixes; reserved layout bits remain rejected. Returns the number of
/// initialized bytes and exact source consumption. Trailing bytes are left for
/// the caller's boundary policy. On error, destination contents are unspecified.
/// Sequence, field, cumulative and nesting accounting remain active; neither
/// element spans nor destination backing are allocated by this function.
///
/// # Errors
/// Returns a fixed framing or resource error for malformed input, exceeded
/// limits, or a declared count larger than the caller's destination.
#[doc(hidden)]
pub fn decode_byte_element_sequence_into(
    bytes: &[u8],
    destination: &mut [u8],
) -> Result<(usize, usize), Error> {
    let (count, _) = read_seq_len_slice(bytes)?;
    let flags = effective_decode_flags().unwrap_or_else(default_encode_flags);
    validate_header_flags(flags)?;
    if count > destination.len() {
        return Err(Error::LengthMismatch);
    }
    let mut index = 0;
    let used = visit_binary_sequence_with_count(bytes, flags, count, |span| {
        let element = span.get(bytes)?;
        record_slice_access(element, span.len());
        // A byte has a total, fixed-width scalar decoder. Retain the same
        // field/depth gates without installing the arbitrary-decoder panic
        // hook (whose process-lived Box is outside this caller's custody).
        check_decode_field_length(
            u64::try_from(element.len()).map_err(|_| Error::LengthMismatch)?,
        )?;
        let _depth = DecodeDepthGuard::enter()?;
        let value = read_byte_value(element)?;
        if element.len() != 1 {
            return Err(Error::LengthMismatch);
        }
        destination[index] = value;
        index += 1;
        Ok(())
    })?;
    note_payload_access(bytes, used);
    Ok((count, used))
}

/// The scalar relation shared by u8 slice, archived and element decoding.
pub(super) fn read_byte_value(bytes: &[u8]) -> Result<u8, Error> {
    bytes.first().copied().ok_or(Error::LengthMismatch)
}

/// Visit every length-prefixed element span of a sequence with a known count.
///
/// Returns the total sequence payload length consumed from the front of `bytes`.
/// The caller obtains `count` through the original sequence admission kernel and
/// retains the advertised layout/decode context. This allocates no span or element graph.
/// A containing field must still require complete consumption and decode each element
/// with its canonical leaf kernel. This traversal authenticates no application value.
///
/// # Errors
/// Preserves the original count, advertised layout, span, field and cumulative refusal.
#[doc(hidden)]
pub fn visit_binary_sequence_with_count(
    bytes: &[u8],
    flags: u8,
    count: usize,
    mut visit: impl FnMut(SequenceSpan) -> Result<(), Error>,
) -> Result<usize, Error> {
    validate_header_flags(flags)?;
    let (declared_count, mut offset) = inspect_seq_len_slice(bytes)?;
    if declared_count != count {
        return Err(Error::LengthMismatch);
    }
    validate_binary_sequence_reservation(bytes, flags, count)?;
    for _ in 0..count {
        let tail = bytes.get(offset..).ok_or(Error::LengthMismatch)?;
        let (elem_len, header_len) = read_len_from_slice_with_flags(tail, flags)?;
        let start = offset
            .checked_add(header_len)
            .ok_or(Error::LengthMismatch)?;
        let end = start.checked_add(elem_len).ok_or(Error::LengthMismatch)?;
        if end > bytes.len() {
            return Err(Error::LengthMismatch);
        }
        visit(SequenceSpan { start, end })?;
        offset = end;
    }
    Ok(offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode(values: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        write_element_sequence::<u8, _>(&mut Encoder::for_buffer(&mut bytes), values.iter())
            .unwrap();
        bytes
    }

    #[test]
    fn caller_storage_matches_generic_sequence_under_every_advertised_layout() {
        for flags in [0, header_flags::COMPACT_LEN] {
            let _flags = DecodeFlagsGuard::enter(flags);
            for values in [&[][..], &[0x11, 0x22, 0x33][..]] {
                let bytes = encode(values);
                let mut output = [0; 3];
                let (len, used) = decode_byte_element_sequence_into(&bytes, &mut output).unwrap();
                let (generic, generic_used) =
                    decode_element_sequence_from_slice_serial::<u8>(&bytes).unwrap();
                assert_eq!(len, values.len());
                assert_eq!(&output[..len], values);
                assert_eq!(generic, values);
                assert_eq!(used, generic_used);
                assert_eq!(used, bytes.len());
                let mut trailing = bytes.clone();
                trailing.extend_from_slice(&[0xff, 0x00]);
                assert_eq!(
                    decode_byte_element_sequence_into(&trailing, &mut output).unwrap(),
                    (len, used)
                );
                if !values.is_empty() {
                    assert!(matches!(
                        decode_byte_element_sequence_into(&bytes, &mut output[..len - 1]),
                        Err(Error::LengthMismatch)
                    ));
                }
            }
        }
    }

    #[test]
    fn truncated_element_framing_is_rejected_before_any_plan_allocation() {
        for flags in [0, header_flags::COMPACT_LEN] {
            let _flags = DecodeFlagsGuard::enter(flags);
            // Four declared elements need at least four element prefixes; only one
            // one-byte element follows the count.
            let mut bytes = 4_u64.to_le_bytes().to_vec();
            write_len_to_vec_with_flags(&mut bytes, 1, flags);
            bytes.push(0x51);
            // Count admission keeps its existing per-element charge. No credit remains
            // for a SequenceSpan allocation; the framing reason must win first.
            let limits = DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 4, usize::MAX);
            let (result, usage) =
                with_decode_limits_measured(limits, || plan_binary_sequence(&bytes, flags));
            assert!(
                matches!(result, Err(Error::LengthMismatch)),
                "flags {flags:#x}"
            );
            assert_eq!(usage.total_allocated_bytes(), 4, "flags {flags:#x}");
        }
    }

    #[test]
    fn malformed_lengths_offsets_and_limits_share_the_canonical_relation() {
        for flags in [0, header_flags::COMPACT_LEN] {
            let _flags = DecodeFlagsGuard::enter(flags);
            let valid = encode(&[0x41, 0x42]);
            let mut output = [0; 2];
            let mut bad = valid.clone();
            bad[8] = 3;
            assert!(decode_byte_element_sequence_into(&bad, &mut output).is_err());
            assert!(decode_element_sequence_from_slice_serial::<u8>(&bad).is_err());
            for len in 0..valid.len() {
                assert!(decode_byte_element_sequence_into(&valid[..len], &mut output).is_err());
                assert!(decode_element_sequence_from_slice_serial::<u8>(&valid[..len]).is_err());
            }
            for limits in [
                DecodeLimits::new(1, usize::MAX, usize::MAX, usize::MAX, usize::MAX),
                DecodeLimits::new(usize::MAX, 0, usize::MAX, usize::MAX, usize::MAX),
                DecodeLimits::new(usize::MAX, usize::MAX, 1, usize::MAX, usize::MAX),
                DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 1, usize::MAX),
                DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, 0),
            ] {
                assert!(
                    with_decode_limits(limits, || decode_byte_element_sequence_into(
                        &valid,
                        &mut output
                    ))
                    .unwrap_err()
                    .is_decode_resource_limit()
                );
            }
        }
    }

    #[test]
    fn fixed_value_error_preserves_display_without_becoming_a_resource_failure() {
        let error = Error::InvalidValue {
            context: "public key",
        };
        assert_eq!(error.to_string(), "invalid public key");
        assert!(!error.is_decode_resource_limit());
    }

    #[test]
    fn original_borrowed_sequence_visitor_rejects_reserved_layout_count_and_truncated_spans() {
        for flags in [0, header_flags::COMPACT_LEN] {
            let _flags = DecodeFlagsGuard::enter(flags);
            let values = [0x11, 0x22, 0x33];
            let bytes = encode(&values);
            let (count, _) = read_seq_len_slice(&bytes).unwrap();
            let mut visited = Vec::new();
            let used = visit_binary_sequence_with_count(&bytes, flags, count, |span| {
                assert!(std::ptr::eq(
                    span.get(&bytes)?.as_ptr(),
                    bytes[span.start..].as_ptr()
                ));
                visited.push(span.get(&bytes)?[0]);
                Ok(())
            })
            .unwrap();
            assert_eq!(visited, values);
            assert_eq!(used, bytes.len());
            assert!(
                visit_binary_sequence_with_count(&bytes, flags, count + 1, |_| Ok(())).is_err()
            );
            assert!(
                visit_binary_sequence_with_count(&bytes[..bytes.len() - 1], flags, count, |_| Ok(
                    ()
                ))
                .is_err()
            );
            assert!(visit_binary_sequence_with_count(&bytes, 0xff, count, |_| Ok(())).is_err());
            let mut trailing = bytes.clone();
            trailing.push(0x55);
            assert_eq!(
                visit_binary_sequence_with_count(&trailing, flags, count, |_| Ok(())).unwrap(),
                used,
                "enclosing canonical field must independently reject this explicit suffix"
            );
        }
    }
}
