//! Exact Norito witness framing, bounded shapes, and live-allocation erasure controls.

use super::super::private_table::inspection;
use super::*;
use core::ops::Range;
use std::io::Write as _;

fn witness() -> ZkX509WitnessV1 {
    ZkX509WitnessV1 {
        certificate_chain_der: vec![vec![0x30, 0], vec![0x30, 0]],
        crl_der: vec![0x30, 0],
        ca_membership_path: ZkX509CaMembershipPathV1 {
            index: 4_095,
            siblings: core::array::from_fn(|index| [index as u8; 32]),
        },
        wallet_ownership_signature_rs: [0x30; ZK_X509_WALLET_SIGNATURE_RS_BYTES_V1],
        attribute_openings: vec![
            ZkX509AttributeOpeningV1 {
                index: 0,
                salt: [0x11; ZK_X509_ATTRIBUTE_SALT_BYTES_V1],
            },
            ZkX509AttributeOpeningV1 {
                index: 3,
                salt: [0x22; ZK_X509_ATTRIBUTE_SALT_BYTES_V1],
            },
        ],
    }
}
fn maximum_witness() -> ZkX509WitnessV1 {
    let mut value = witness();
    value.certificate_chain_der = vec![
        vec![0x35; ZK_X509_RFC5280_MAX_TOP_LEVEL_DOCUMENT_BYTES_V1];
        ZK_X509_MAX_CHAIN_DEPTH_V1
    ];
    value.crl_der = vec![0x37; ZK_X509_CRL_COMMITMENT_MAX_DER_BYTES_V1];
    value.attribute_openings = (0..4)
        .map(|index| ZkX509AttributeOpeningV1 {
            index,
            salt: [0x39; ZK_X509_ATTRIBUTE_SALT_BYTES_V1],
        })
        .collect();
    value
}
fn payload(frame: &[u8]) -> &[u8] {
    norito::core::from_bytes_view(frame).unwrap().as_bytes()
}
fn reframe(bytes: &[u8]) -> Vec<u8> {
    // Test-only exact fixed payload, framed by the real Norito implementation.
    let layout =
        norito::core::FixedFrameLayout::<ZkX509WitnessV1>::new(bytes.len(), WITNESS_FLAGS_V1)
            .unwrap();
    let mut frame = Vec::with_capacity(layout.frame_len());
    layout.write(&mut frame, bytes).unwrap();
    frame
}
fn field_at(bytes: &[u8], offset: &mut usize) -> Range<usize> {
    let length = usize::try_from(u64::from_le_bytes(
        bytes[*offset..*offset + 8].try_into().unwrap(),
    ))
    .unwrap();
    *offset += 8;
    let range = *offset..*offset + length;
    *offset = range.end;
    range
}
fn fields(bytes: &[u8]) -> Vec<Range<usize>> {
    let mut offset = 0;
    let mut fields = Vec::new();
    while offset < bytes.len() {
        fields.push(field_at(bytes, &mut offset));
    }
    assert_eq!(offset, bytes.len());
    fields
}
fn replace_count(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
fn assert_cleared(observations: &[inspection::ErasureObservationV1]) {
    assert!(observations.iter().all(|item| item.nonzero_after == 0));
}
fn expected_cells(value: &ZkX509WitnessV1) -> usize {
    value
        .certificate_chain_der
        .iter()
        .map(Vec::len)
        .sum::<usize>()
        + value.crl_der.len()
        + 1
        + ZK_X509_CA_COMPACT_TREE_DEPTH_V1 * 32
        + ZK_X509_WALLET_SIGNATURE_RS_BYTES_V1
        + value.attribute_openings.len() * (1 + ZK_X509_ATTRIBUTE_SALT_BYTES_V1)
}

#[test]
fn witness_codec_round_trips_exactly() {
    let original = witness();
    let encoded = original.encode_v1().unwrap();
    assert_eq!(&encoded[..4], b"NRT0");
    let header = Header::read(encoded.as_slice()).unwrap();
    assert_eq!(
        header.schema,
        norito::schema::identity::frame_hash::<ZkX509WitnessV1>()
    );
    assert_eq!(header.flags, 0);
    assert_eq!(header.compression, norito::core::Compression::None);
    assert_eq!(
        ZkX509WitnessV1::decode_exact_v1(&encoded).unwrap(),
        original
    );
    // Independent writer and standard bounded frame entrypoint exercise the
    // actual derived payload and the custom slice decoder in both directions.
    let _flags = norito::core::DecodeFlagsGuard::enter(0);
    assert_eq!(norito::core::to_bytes(&original).unwrap(), encoded);
    assert_eq!(
        norito::core::decode_from_bytes_with_limits::<ZkX509WitnessV1>(
            &encoded,
            witness_decode_limits_v1()
        )
        .unwrap(),
        original
    );
    norito::verify_exact_frame(&original, &encoded).unwrap();
}

#[test]
fn witness_codec_rejects_every_truncation_and_suffix() {
    let encoded = witness().encode_v1().unwrap();
    for length in 0..encoded.len() {
        assert!(
            ZkX509WitnessV1::decode_exact_v1(&encoded[..length]).is_err(),
            "frame truncation {length}"
        );
    }
    let mut suffixed = encoded;
    suffixed.push(0);
    assert_eq!(
        ZkX509WitnessV1::decode_exact_v1(&suffixed),
        Err(ZkX509WitnessCodecErrorV1::TrailingBytes)
    );
    let mut maximum = maximum_witness().encode_v1().unwrap();
    maximum.push(0);
    assert_eq!(
        ZkX509WitnessV1::decode_exact_v1(&maximum),
        Err(ZkX509WitnessCodecErrorV1::TrailingBytes)
    );
}

#[test]
fn witness_codec_rejects_noncanonical_counts_lengths_and_openings() {
    let mut shallow = witness();
    shallow.certificate_chain_der.pop();
    assert_eq!(
        shallow.encode_v1(),
        Err(ZkX509WitnessCodecErrorV1::InvalidChainDepth)
    );
    let mut empty_certificate = witness();
    empty_certificate.certificate_chain_der[0].clear();
    assert_eq!(
        empty_certificate.encode_v1(),
        Err(ZkX509WitnessCodecErrorV1::InvalidCertificateLength)
    );
    let mut oversized_certificate = witness();
    oversized_certificate.certificate_chain_der[1] =
        vec![0; ZK_X509_RFC5280_MAX_TOP_LEVEL_DOCUMENT_BYTES_V1 + 1];
    assert_eq!(
        oversized_certificate.encode_v1(),
        Err(ZkX509WitnessCodecErrorV1::InvalidCertificateLength)
    );
    let mut oversized_crl = witness();
    oversized_crl.crl_der = vec![0; ZK_X509_CRL_COMMITMENT_MAX_DER_BYTES_V1 + 1];
    assert_eq!(
        oversized_crl.encode_v1(),
        Err(ZkX509WitnessCodecErrorV1::InvalidCrlLength)
    );
    let mut duplicate = witness();
    duplicate.attribute_openings[1].index = duplicate.attribute_openings[0].index;
    assert_eq!(
        duplicate.encode_v1(),
        Err(ZkX509WitnessCodecErrorV1::InvalidAttributeOpenings)
    );
    let mut reordered = witness();
    reordered.attribute_openings.swap(0, 1);
    assert_eq!(
        reordered.encode_v1(),
        Err(ZkX509WitnessCodecErrorV1::InvalidAttributeOpenings)
    );
    let mut index = witness();
    index.ca_membership_path.index = ZK_X509_CA_COMPACT_TREE_CAPACITY_V1 as u16;
    assert_eq!(
        index.encode_v1(),
        Err(ZkX509WitnessCodecErrorV1::InvalidCaPathIndex)
    );
}

#[test]
fn witness_decoder_rejects_raw_header_count_and_length_attacks() {
    let encoded = witness().encode_v1().unwrap();
    for offset in 0..Header::SIZE {
        let mut changed = encoded.clone();
        changed[offset] ^= 1;
        assert!(
            ZkX509WitnessV1::decode_exact_v1(&changed).is_err(),
            "header byte {offset}"
        );
    }
    let original = payload(&encoded);
    let top = fields(original);
    assert_eq!(top.len(), 5);
    for count in [0, 1, 4, u64::MAX] {
        let mut changed = original.to_vec();
        replace_count(&mut changed, top[0].start, count);
        assert_eq!(
            ZkX509WitnessV1::decode_exact_v1(&reframe(&changed)),
            Err(ZkX509WitnessCodecErrorV1::InvalidChainDepth)
        );
    }
    let mut chain_offset = top[0].start + 8;
    let certificate0 = field_at(original, &mut chain_offset);
    let certificate1 = field_at(original, &mut chain_offset);
    for (offset, maximum, expected) in [
        (
            certificate0.start,
            ZK_X509_RFC5280_MAX_TOP_LEVEL_DOCUMENT_BYTES_V1,
            ZkX509WitnessCodecErrorV1::InvalidCertificateLength,
        ),
        (
            certificate1.start,
            ZK_X509_RFC5280_MAX_TOP_LEVEL_DOCUMENT_BYTES_V1,
            ZkX509WitnessCodecErrorV1::InvalidCertificateLength,
        ),
        (
            top[1].start,
            ZK_X509_CRL_COMMITMENT_MAX_DER_BYTES_V1,
            ZkX509WitnessCodecErrorV1::InvalidCrlLength,
        ),
    ] {
        for declared in [0, (maximum + 1) as u64, u64::MAX] {
            let mut changed = original.to_vec();
            replace_count(&mut changed, offset, declared);
            assert_eq!(
                ZkX509WitnessV1::decode_exact_v1(&reframe(&changed)),
                Err(expected),
                "declared {declared} at {offset}"
            );
        }
    }
    for offset in [0, top[0].start + 8, top[1].start - 8, top[2].start - 8] {
        let mut changed = original.to_vec();
        replace_count(&mut changed, offset, u64::MAX);
        assert!(ZkX509WitnessV1::decode_exact_v1(&reframe(&changed)).is_err());
    }
}

#[test]
fn witness_decoder_rejects_duplicate_reordered_and_excess_openings() {
    for indices in [vec![0, 0], vec![3, 0], vec![0, 4], vec![0, 1, 2, 3, 3]] {
        let mut value = witness();
        value.attribute_openings = indices
            .into_iter()
            .map(|index| ZkX509AttributeOpeningV1 {
                index,
                salt: [0x57; 32],
            })
            .collect();
        let encoded = value.encode_unchecked_for_test_v1().unwrap();
        assert_eq!(
            ZkX509WitnessV1::decode_exact_v1(&encoded),
            Err(ZkX509WitnessCodecErrorV1::InvalidAttributeOpenings)
        );
    }
    let encoded = witness().encode_v1().unwrap();
    let mut changed = payload(&encoded).to_vec();
    let count = fields(&changed)[4].start;
    replace_count(&mut changed, count, u64::MAX);
    assert_eq!(
        ZkX509WitnessV1::decode_exact_v1(&reframe(&changed)),
        Err(ZkX509WitnessCodecErrorV1::InvalidAttributeOpenings)
    );
}

#[test]
fn witness_codec_pins_norito_little_endian_index_and_rejects_boundary_mutation() {
    let encoded = witness().encode_v1().unwrap();
    let mut changed = payload(&encoded).to_vec();
    let path = fields(&changed)[2].clone();
    let index = fields(&changed[path.clone()])[0].start + path.start;
    assert_eq!(&changed[index..index + 2], &[0xff, 0x0f]);
    changed[index..index + 2].copy_from_slice(&4096_u16.to_le_bytes());
    assert_eq!(
        ZkX509WitnessV1::decode_exact_v1(&reframe(&changed)),
        Err(ZkX509WitnessCodecErrorV1::InvalidCaPathIndex)
    );
    let mut first = witness();
    first.ca_membership_path.index = 0;
    assert_eq!(
        ZkX509WitnessV1::decode_exact_v1(&first.encode_v1().unwrap()).unwrap(),
        first
    );
}

#[test]
fn private_witness_debug_is_redacted_and_recursive_zeroize_covers_every_field() {
    let mut value = witness();
    assert_eq!(format!("{value:?}"), "ZkX509WitnessV1 { [REDACTED] }");
    value.zeroize();
    assert!(value.certificate_chain_der.is_empty());
    assert!(value.crl_der.is_empty());
    assert_eq!(value.ca_membership_path.index, 0);
    assert!(
        value
            .ca_membership_path
            .siblings
            .iter()
            .flatten()
            .all(|byte| *byte == 0)
    );
    assert!(
        value
            .wallet_ownership_signature_rs
            .iter()
            .all(|byte| *byte == 0)
    );
    assert!(value.attribute_openings.is_empty());
}

#[test]
fn witness_decoder_clears_partial_private_fields_at_every_truncation() {
    let encoded = witness().encode_v1().unwrap();
    for length in 0..encoded.len() {
        let (result, observations) =
            inspection::observe_v1(|| ZkX509WitnessV1::decode_exact_v1(&encoded[..length]));
        assert!(result.is_err());
        assert!(
            observations.is_empty(),
            "framing rejected before any private allocation"
        );
    }
    let original = payload(&encoded);
    let complete_chain_end = fields(original)[0].end;
    for length in 0..original.len() {
        // Reframe every shortened payload so its real CRC/header pass and the
        // bounded field parser, including partial private ownership, executes.
        let frame = reframe(&original[..length]);
        let (result, observations) =
            inspection::observe_v1(|| ZkX509WitnessV1::decode_exact_v1(&frame));
        assert!(result.is_err(), "payload truncation {length}");
        assert_cleared(&observations);
        if length >= complete_chain_end {
            assert!(
                observations.iter().any(|item| item.nonzero_before > 0),
                "owned certificates at {length} were not erased"
            );
        }
    }
}

#[test]
fn witness_decoder_clears_late_invalid_fields_and_transferred_owner() {
    let canonical = witness();
    let encoded = canonical.encode_v1().unwrap();
    let assert_erased = |observations: Vec<inspection::ErasureObservationV1>| {
        assert_eq!(
            observations.iter().map(|item| item.cells).sum::<usize>(),
            expected_cells(&canonical)
        );
        assert!(observations.iter().any(|item| item.nonzero_before > 0));
        assert_cleared(&observations);
    };
    let mut duplicate = canonical.clone();
    duplicate.attribute_openings[1].index = 0;
    let malformed = duplicate.encode_unchecked_for_test_v1().unwrap();
    let (result, observations) =
        inspection::observe_v1(|| ZkX509WitnessV1::decode_exact_v1(&malformed));
    assert_eq!(
        result,
        Err(ZkX509WitnessCodecErrorV1::InvalidAttributeOpenings)
    );
    assert_erased(observations);
    let mut suffixed = payload(&encoded).to_vec();
    suffixed.push(0);
    let frame = reframe(&suffixed);
    let (result, observations) =
        inspection::observe_v1(|| ZkX509WitnessV1::decode_exact_v1(&frame));
    assert_eq!(result, Err(ZkX509WitnessCodecErrorV1::TrailingBytes));
    assert_erased(observations);
    for unwind in [false, true] {
        let decoded = ZkX509WitnessV1::decode_exact_v1(&encoded).unwrap();
        assert_eq!(decoded, canonical);
        let ((), observations) = inspection::observe_v1(|| {
            let result = std::panic::catch_unwind(move || {
                let _owner = decoded;
                if unwind {
                    panic!("decoded owner unwind");
                }
            });
            assert_eq!(result.is_err(), unwind);
        });
        assert_erased(observations);
    }
    assert_eq!(canonical.encode_v1().unwrap(), encoded);
}

#[test]
fn witness_encoded_length_covers_empty_and_maximum_disclosure_shapes() {
    let mut empty = witness();
    empty.attribute_openings.clear();
    let bytes = empty.encode_v1().unwrap();
    assert_eq!(encoded_witness_len_v1(&empty).unwrap(), bytes.len());
    // These pins come from the actual derived Norito encoding, independently
    // compared with the source-dimensional maximum below.
    assert_eq!(bytes.len(), 3_776);
    let maximum = maximum_witness();
    let bytes = maximum.encode_v1().unwrap();
    assert_eq!(encoded_witness_len_v1(&maximum).unwrap(), bytes.len());
    assert_eq!(bytes.len(), 20_398);
    assert_eq!(bytes.len(), MAX_WITNESS_FRAME_BYTES_V1);
    assert_eq!(payload(&bytes).len(), MAX_WITNESS_PAYLOAD_BYTES_V1);
    assert_eq!(ZkX509WitnessV1::decode_exact_v1(&bytes).unwrap(), maximum);
}

#[test]
fn witness_norito_rejects_retired_magic_wrong_schema_compression_and_flags() {
    let value = witness();
    let frame = value.encode_v1().unwrap();
    let mut retired = vec![0; frame.len()];
    retired[..8].copy_from_slice(b"IRX509W1");
    assert_eq!(
        ZkX509WitnessV1::decode_exact_v1(&retired),
        Err(ZkX509WitnessCodecErrorV1::InvalidHeader)
    );
    for (offset, value) in [(6, frame[6] ^ 1), (22, 1), (Header::SIZE - 1, 2)] {
        let mut changed = frame.clone();
        changed[offset] = value;
        assert_eq!(
            ZkX509WitnessV1::decode_exact_v1(&changed),
            Err(ZkX509WitnessCodecErrorV1::InvalidHeader)
        );
    }
    let alternative = {
        let _flags = norito::core::DecodeFlagsGuard::enter(2);
        norito::core::to_bytes(&value).unwrap()
    };
    assert_eq!(
        ZkX509WitnessV1::decode_exact_v1(&alternative),
        Err(ZkX509WitnessCodecErrorV1::InvalidHeader)
    );
    let mut checksum = frame.clone();
    *checksum.last_mut().unwrap() ^= 1;
    let (result, observations) =
        inspection::observe_v1(|| ZkX509WitnessV1::decode_exact_v1(&checksum));
    assert_eq!(result, Err(ZkX509WitnessCodecErrorV1::InvalidHeader));
    assert!(observations.is_empty());
    let mut bytes = frame[..Header::SIZE].to_vec();
    bytes[23..31].copy_from_slice(&(MAX_WITNESS_PAYLOAD_BYTES_V1 as u64 + 1).to_le_bytes());
    assert_eq!(
        ZkX509WitnessV1::decode_exact_v1(&bytes),
        Err(ZkX509WitnessCodecErrorV1::FrameTooLarge)
    );
}

#[test]
fn witness_decode_honors_stricter_outer_element_field_and_allocation_limits() {
    let frame = witness().encode_v1().unwrap();
    for limits in [
        norito::DecodeLimits::new(1, usize::MAX, usize::MAX, usize::MAX, 32),
        norito::DecodeLimits::new(4096, 1, usize::MAX, usize::MAX, 32),
        norito::DecodeLimits::new(4096, usize::MAX, 1, usize::MAX, 32),
        norito::DecodeLimits::new(4096, usize::MAX, usize::MAX, 1, 32),
    ] {
        let (result, observations) = inspection::observe_v1(|| {
            norito::core::with_decode_limits_scope(limits, || {
                ZkX509WitnessV1::decode_exact_v1(&frame)
            })
        });
        assert_eq!(result, Err(ZkX509WitnessCodecErrorV1::ResourceLimit));
        assert_cleared(&observations);
    }
    // A late allocation failure clears the first copied certificate too.
    let limits = norito::DecodeLimits::new(
        4096,
        usize::MAX,
        usize::MAX,
        2 * core::mem::size_of::<Vec<u8>>() + 2,
        32,
    );
    let (result, observations) = inspection::observe_v1(|| {
        norito::core::with_decode_limits_scope(limits, || ZkX509WitnessV1::decode_exact_v1(&frame))
    });
    assert_eq!(result, Err(ZkX509WitnessCodecErrorV1::ResourceLimit));
    assert!(observations.iter().any(|item| item.nonzero_before > 0));
    assert_cleared(&observations);
    assert_eq!(ZkX509WitnessV1::decode_exact_v1(&frame).unwrap(), witness());
}

#[test]
fn witness_writer_never_grows_and_clears_partial_success_error_and_unwind() {
    let value = witness();
    let expected = value.encode_v1().unwrap();
    for unwind in [false, true] {
        let ((), observations) = inspection::observe_v1(|| {
            let result = std::panic::catch_unwind(|| {
                let mut writer = PrivateWitnessWriterV1::new(expected.len() - 1).unwrap();
                let address = writer.bytes.as_ptr();
                let capacity = writer.bytes.capacity();
                let _flags = norito::core::DecodeFlagsGuard::enter(0);
                assert!(norito::core::write_frame_to_writer(&value, &mut writer).is_err());
                assert_eq!(writer.bytes.as_ptr(), address);
                assert_eq!(writer.bytes.capacity(), capacity);
                assert!(!writer.bytes.is_empty());
                if unwind {
                    panic!("private writer unwind");
                }
            });
            assert_eq!(result.is_err(), unwind);
        });
        assert!(observations.iter().any(|item| item.nonzero_before > 0));
        assert_cleared(&observations);
    }
    let ((), observations) = inspection::observe_v1(|| {
        let mut writer = PrivateWitnessWriterV1::new(expected.len()).unwrap();
        let address = writer.bytes.as_ptr();
        assert_eq!(writer.write(&expected).unwrap(), expected.len());
        writer.flush().unwrap();
        assert_eq!(writer.bytes.as_ptr(), address);
        assert_eq!(&**writer.bytes, &expected);
    });
    assert_eq!(
        observations.iter().map(|item| item.cells).sum::<usize>(),
        expected.len()
    );
    assert_cleared(&observations);
    assert!(PrivateWitnessWriterV1::new(MAX_WITNESS_FRAME_BYTES_V1 + 1).is_err());
}

#[test]
fn witness_codec_restores_ambient_flags_and_rejects_noncanonical_fixed_fields() {
    let value = witness();
    let frame = value.encode_v1().unwrap();
    {
        let _flags = norito::core::DecodeFlagsGuard::enter(2);
        assert_eq!(value.encode_v1().unwrap(), frame);
        assert_eq!(ZkX509WitnessV1::decode_exact_v1(&frame).unwrap(), value);
        assert_eq!(norito::core::effective_decode_flags(), Some(2));
    }
    let original = payload(&frame);
    let top = fields(original);
    for index in [2, 3] {
        let mut changed = original.to_vec();
        let start = top[index].start;
        // Every fixed field must have its exact shape, including nested
        // generic-array element widths; accepting short raw digests is forbidden.
        replace_count(&mut changed, start - 8, (top[index].len() - 1) as u64);
        changed.remove(top[index].end - 1);
        assert!(ZkX509WitnessV1::decode_exact_v1(&reframe(&changed)).is_err());
    }
}

#[test]
fn witness_decoder_clears_partially_filled_nested_path_and_opening() {
    let encoded = witness().encode_v1().unwrap();
    let original = payload(&encoded);
    let top = fields(original);
    let path_fields = fields(&original[top[2].clone()]);
    let siblings_start = top[2].start + path_fields[1].start;
    let mut sibling_position = siblings_start;
    let _first_digest = field_at(original, &mut sibling_position);
    let second_digest = field_at(original, &mut sibling_position);
    let digest_fields = fields(&original[second_digest.clone()]);
    let openings_start = top[4].start;
    let mut opening_position = openings_start + 8;
    let first_opening = field_at(original, &mut opening_position);
    let first_opening_fields = fields(&original[first_opening.clone()]);
    // A late fixed-width child error occurs after populated path bytes or an
    // opening index have been assigned directly to the final clearing owner.
    for length_offset in [
        second_digest.start + digest_fields[5].start - 8,
        first_opening.start + first_opening_fields[1].start - 8,
    ] {
        let mut changed = original.to_vec();
        replace_count(&mut changed, length_offset, 0);
        let malformed = reframe(&changed);
        let (result, observations) =
            inspection::observe_v1(|| ZkX509WitnessV1::decode_exact_v1(&malformed));
        assert!(result.is_err());
        assert!(observations.iter().any(|item| item.nonzero_before > 0));
        assert_cleared(&observations);
        if length_offset == second_digest.start + digest_fields[5].start - 8 {
            assert!(
                observations
                    .iter()
                    .any(|item| item.cells == 32 && item.nonzero_before == 5),
                "the five populated bytes in the second digest must clear before release"
            );
        } else {
            assert_eq!(
                observations.iter().map(|item| item.cells).sum::<usize>(),
                expected_cells(&witness()) - (1 + ZK_X509_ATTRIBUTE_SALT_BYTES_V1),
                "the partially populated first opening must remain in the final owner"
            );
        }
    }
}

#[test]
fn witness_norito_decodes_unaligned_input_without_aligned_private_scratch() {
    let original = witness();
    let frame = original.encode_v1().unwrap();
    let mut storage = Vec::with_capacity(frame.len() + 1);
    storage.push(0);
    storage.extend_from_slice(&frame);
    let (decoded, observations) =
        inspection::observe_v1(|| ZkX509WitnessV1::decode_exact_v1(&storage[1..]).unwrap());
    assert_eq!(decoded, original);
    // Only the final owner exists after successful decode, so no intermediate
    // clearing owner was destroyed or copied into another allocation.
    assert!(observations.is_empty());
    let ((), observations) = inspection::observe_v1(|| drop(decoded));
    assert_eq!(
        observations.iter().map(|item| item.cells).sum::<usize>(),
        expected_cells(&original)
    );
    assert_cleared(&observations);
}
