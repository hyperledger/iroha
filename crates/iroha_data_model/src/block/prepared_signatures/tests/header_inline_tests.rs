//! Original complete header transport, canonical commitments and shared block custody.
use super::*;
use crate::confidential::ConfidentialFeatureDigest;
use iroha_allocation::{AllocationRefusal, ChargedBufferError};

fn digest() -> ConfidentialFeatureDigest {
    ConfidentialFeatureDigest::new(Some([17; 32]), Some(23), Some(29), Some(31), Some([37; 32]))
}
fn header_block(count: usize, features: Option<ConfidentialFeatureDigest>) -> SignedBlock {
    // Transport/proposal commitment fixture only: these signatures and parent
    // bytes do not confer execution, confidential policy or native finality.
    let mut original = fixture(count);
    original.payload.header = BlockHeader::new(
        std::num::NonZeroU64::new(7).unwrap(),
        Some(iroha_crypto::HashOf::from_untyped_unchecked(Hash::new(
            b"inline header original parent",
        ))),
        None,
        123_456_789,
        3,
    );
    original.payload.header.set_confidential_features(features);
    original.validate_proposal_commitments().unwrap();
    original
}

#[test]
fn complete_inline_header_child_keeps_original_block_commitments_hash_and_shared_owner() {
    for count in [0, 4, 31] {
        for features in [None, Some(digest())] {
            let original = header_block(count, features);
            let wire = original.encode_wire().unwrap();
            let ordinary = crate::block::decode_framed_signed_block(&wire).unwrap();
            assert_eq!(ordinary, original);
            assert_eq!(ordinary.header().hash(), original.header().hash());
            assert_eq!(ordinary.header().confidential_features(), features);
            ordinary.validate_proposal_commitments().unwrap();
            let pool = AllocationBudget::new(1 << 20);
            let (source, span) = source_for(&original, &pool);
            let floor = pool.reserved_bytes();
            let pointer = source.as_slice().as_ptr();
            let hash = Hash::new(source.as_slice());
            let mut decoder = PreparedSignedBlockSignaturesDecode::new(&pool).unwrap();
            let admitted = decoder
                .decode(&source, span, norito::canonical_decode_limits(wire.len()))
                .unwrap();
            assert_eq!(admitted, original);
            assert_eq!(admitted.header(), original.header());
            assert_eq!(admitted.header().hash(), original.header().hash());
            assert_eq!(admitted.encode_wire().unwrap(), wire);
            admitted.validate_proposal_commitments().unwrap();
            assert!(admitted.signatures.admitted_to(&pool));
            assert!(BlockSignatures::ptr_eq(
                &admitted.signatures,
                decoder.retained_signatures(&source).unwrap().unwrap()
            ));
            let retry = decoder
                .decode(&source, span, norito::canonical_decode_limits(wire.len()))
                .unwrap();
            assert!(retry.same_signature_custody(&admitted));
            assert_eq!(retry.header(), original.header());
            drop(retry);
            let held = SharedSignedBlock::reserve(&pool)
                .unwrap()
                .initialize(admitted);
            let header_address = std::ptr::from_ref(&held.payload.header);
            let clone = held.clone();
            assert_eq!(std::ptr::from_ref(&clone.payload.header), header_address);
            drop(held);
            decoder.clear_consumed();
            drop(decoder);
            assert_eq!(std::ptr::from_ref(&clone.payload.header), header_address);
            assert_eq!(clone.header(), original.header());
            assert_eq!(clone.header().hash(), original.header().hash());
            assert_eq!(clone.encode_wire().unwrap(), wire);
            clone.validate_proposal_commitments().unwrap();
            assert_eq!(source.as_slice().as_ptr(), pointer);
            assert_eq!(Hash::new(source.as_slice()), hash);
            drop(clone);
            assert_eq!(pool.reserved_bytes(), floor);
            drop(source);
            assert_eq!(pool.reserved_bytes(), 0);
        }
    }
}

#[test]
fn header_block_original_first_field_enclosing_cause_keeps_same_source_and_retry() {
    use norito::core::{
        DecodeAttemptErrorKind, DecodeLimits, DecodeResourceError, with_decode_limits_scope,
    };
    // The ordinary complete SignedBlock walk reaches its empty signature sequence
    // before BlockPayload/header. Its original fixed-u64 count occupies eight
    // bytes; the prepared path must preserve that same first refusal.
    // The standalone physical control separately reaches the header's height.
    let original = header_block(0, Some(digest()));
    assert_eq!(
        norito::core::encoded_payload_len(&original.signatures).unwrap(),
        std::mem::size_of::<u64>()
    );
    let wire = original.encode_wire().unwrap();
    // Version byte, Norito header, then the root payload and nothing else.
    let root = wire.len() - 1 - norito::core::Header::SIZE;
    {
        let _canonical =
            norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
        assert_eq!(
            root,
            norito::core::encoded_payload_len(&original).unwrap(),
            "the frame holds exactly the canonical root payload"
        );
    }
    assert!(root > std::mem::size_of::<u64>());
    let pool = AllocationBudget::new(1 << 20);
    let (source, span) = source_for(&original, &pool);
    let floor = pool.reserved_bytes();
    let pointer = source.as_slice().as_ptr();
    let hash = Hash::new(source.as_slice());
    let mut decoder = PreparedSignedBlockSignaturesDecode::new(&pool).unwrap();
    let protocol = DecodeLimits::new(1 << 20, 1 << 20, 1 << 20, 1 << 20, 64);
    let narrow = DecodeLimits::new(1 << 20, 1, 1 << 20, 1 << 20, 64);
    let ordinary =
        with_decode_limits_scope(narrow, || crate::block::decode_framed_signed_block(&wire))
            .unwrap_err();
    assert_eq!(ordinary.kind(), DecodeAttemptErrorKind::EnclosingLimit);
    let ordinary_resource = ordinary.into_error().decode_resource_error();
    assert_eq!(
        ordinary_resource,
        Some(DecodeResourceError::FieldLengthExceeded {
            length: std::mem::size_of::<u64>() as u64,
            limit: 1
        })
    );
    let error =
        with_decode_limits_scope(narrow, || decoder.decode(&source, span, protocol)).unwrap_err();
    let PreparedSignatureBlockError::Decode(PreparedDecodeError::Codec(cause)) = error else {
        panic!(
            "original first field must preserve its enclosing reader through the complete header block"
        );
    };
    assert_eq!(cause.kind(), DecodeAttemptErrorKind::EnclosingLimit);
    assert!(decoder.retained_signatures(&source).unwrap().is_none());
    let retry = decoder.decode(&source, span, protocol).unwrap();
    assert_eq!(retry.header(), original.header());
    assert_eq!(retry.header().hash(), original.header().hash());
    assert_eq!(retry.encode_wire().unwrap(), wire);
    retry.validate_proposal_commitments().unwrap();
    assert!(retry.signatures.admitted_to(&pool));
    assert_eq!(source.as_slice().as_ptr(), pointer);
    assert_eq!(Hash::new(source.as_slice()), hash);
    assert_eq!(cause.kind(), DecodeAttemptErrorKind::EnclosingLimit);
    assert_eq!(
        cause.into_error().decode_resource_error(),
        ordinary_resource
    );
    // The archive-view record is not a child field. Both decoders accept a
    // field ceiling below its complete payload when each actual field fits.
    for field_limit in [root - 1, root] {
        let limits = DecodeLimits::new(1 << 20, field_limit, 1 << 20, 1 << 20, 64);
        let ordinary =
            with_decode_limits_scope(limits, || crate::block::decode_framed_signed_block(&wire))
                .unwrap();
        let admitted =
            with_decode_limits_scope(limits, || decoder.decode(&source, span, protocol)).unwrap();
        assert_eq!(admitted, ordinary);
        assert!(admitted.same_signature_custody(&retry));
        assert_eq!(admitted.header(), original.header());
        assert_eq!(admitted.encode_wire().unwrap(), wire);
        assert_eq!(source.as_slice().as_ptr(), pointer);
        assert_eq!(Hash::new(source.as_slice()), hash);
    }
    drop(retry);
    drop(decoder);
    assert_eq!(pool.reserved_bytes(), floor);
    drop(source);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn complete_header_block_rejects_foreign_changed_truncated_and_wrong_flags_sources_with_original_causes()
 {
    let original = header_block(4, Some(digest()));
    let wire = original.encode_wire().unwrap();
    let pool = AllocationBudget::new(1 << 20);
    let (mut source, span) = source_for(&original, &pool);
    let floor = pool.reserved_bytes();
    let pointer = source.as_slice().as_ptr();
    let hash = Hash::new(source.as_slice());
    let controls = PreparedDecodeWorkspace::allocation_layouts()
        .iter()
        .map(std::alloc::Layout::size)
        .sum::<usize>();
    let limit = floor.checked_add(controls).unwrap().checked_sub(1).unwrap();
    pool.set_limit_bytes(limit);
    let Err(error) = PreparedSignedBlockSignaturesDecode::new(&pool) else {
        panic!("occupied original source must refuse decoder controls before source binding");
    };
    let PreparedSignatureBlockError::Storage(ChargedBufferError::Admission(
        AllocationRefusal::Capacity {
            requested_bytes,
            reserved_bytes,
            limit_bytes,
            ..
        },
    )) = error
    else {
        panic!("original source occupancy must retain its exact capacity cause");
    };
    assert_eq!(requested_bytes, controls);
    assert_eq!(reserved_bytes, floor);
    assert_eq!(limit_bytes, limit);
    assert_eq!(pool.reserved_bytes(), floor);
    assert_eq!(source.as_slice().as_ptr(), pointer);
    assert_eq!(Hash::new(source.as_slice()), hash);
    pool.set_limit_bytes(1 << 20);
    let (copy, _) = source_for(&original, &pool);
    let foreign_pool = AllocationBudget::new(1 << 20);
    let (foreign, _) = source_for(&original, &foreign_pool);
    let mut decoder = PreparedSignedBlockSignaturesDecode::new(&pool).unwrap();
    assert!(matches!(
        decoder.decode(&foreign, span, norito::canonical_decode_limits(wire.len())),
        Err(PreparedSignatureBlockError::Source)
    ));
    assert!(decoder.source.is_none());
    let admitted = decoder
        .decode(&source, span, norito::canonical_decode_limits(wire.len()))
        .unwrap();
    assert!(matches!(
        decoder.decode(&copy, span, norito::canonical_decode_limits(wire.len())),
        Err(PreparedSignatureBlockError::SourceChanged)
    ));
    source.as_mut_slice()[0] ^= 1;
    assert!(matches!(
        decoder.decode(&source, span, norito::canonical_decode_limits(wire.len())),
        Err(PreparedSignatureBlockError::SourceChanged)
    ));
    source.as_mut_slice()[0] ^= 1;
    let retry = decoder
        .decode(&source, span, norito::canonical_decode_limits(wire.len()))
        .unwrap();
    assert!(retry.same_signature_custody(&admitted));
    assert_eq!(retry.header(), admitted.header());
    assert_eq!(retry.header().hash(), admitted.header().hash());
    let mut bad_sources = [0, 1, wire.len() - 1]
        .into_iter()
        .map(|end| wire[..end].to_vec())
        .collect::<Vec<_>>();
    let mut wrong_flags = wire.clone();
    wrong_flags[1 + norito::core::Header::SIZE - 1] ^= 0x80;
    bad_sources.push(wrong_flags);
    for bytes in bad_sources {
        let expected = crate::block::decode_framed_signed_block(&bytes).unwrap_err();
        let mut bad = ChargedBuffer::new(bytes.len(), &pool).unwrap();
        bad.append(&bytes).unwrap();
        let mut fresh = PreparedSignedBlockSignaturesDecode::new(&pool).unwrap();
        let actual = fresh
            .decode(
                &bad,
                SequenceSpan {
                    start: 0,
                    end: bytes.len(),
                },
                norito::canonical_decode_limits(bytes.len()),
            )
            .unwrap_err();
        let actual = match actual {
            PreparedSignatureBlockError::Frame(cause)
            | PreparedSignatureBlockError::Decode(PreparedDecodeError::Codec(cause)) => cause,
            cause => panic!("invalid original frame became custody/refusal error: {cause}"),
        };
        assert_eq!(actual.kind(), expected.kind());
        assert_eq!(
            actual.into_error().to_string(),
            expected.into_error().to_string()
        );
    }
    drop(retry);
    drop(admitted);
    drop(decoder);
    drop(foreign);
    assert_eq!(foreign_pool.reserved_bytes(), 0);
    drop(copy);
    assert_eq!(source.as_slice().as_ptr(), pointer);
    assert_eq!(Hash::new(source.as_slice()), hash);
    drop(source);
    assert_eq!(pool.reserved_bytes(), 0);
}
