//! Actual canonical `SignedBlock` commitment child walk and retained source/error owners.
use super::*;
use crate::da::commitment::DaCommitmentRecord;
use iroha_model_base::topology::LaneId;
fn commitment_fixture(count: usize) -> SignedBlock {
    let mut block = fixture(0);
    let sample = crate::block::tests::sample_da_bundle();
    let commitments = DaCommitmentBundle::new(
        (0..count)
            .map(|i| {
                // Complete codec-custody fixtures, not authenticated Torii service acknowledgements.
                let mut record: DaCommitmentRecord = sample.commitments()[0].clone();
                record.lane_id = LaneId::new(u32::try_from(i).unwrap());
                record.epoch = i as u64;
                record.sequence = i as u64 + 1;
                record.retention_class.governance_tag.0 = if i == 0 {
                    String::new()
                } else {
                    "é漢🙂".repeat(i)
                };
                record.acknowledgement_sig =
                    Signature::from_bytes(&vec![
                        u8::try_from(i).unwrap() + 1;
                        if i % 2 == 0 { 3 } else { 96 }
                    ]);
                record
            })
            .collect(),
    );
    block
        .payload
        .header
        .set_da_commitments_hash(commitments.merkle_commitment());
    block.payload.da_commitments = Some(commitments);
    block
}
#[test]
fn complete_commitment_child_keeps_full_canonical_frame_tag_signature_source_and_original_shared_readers()
 {
    for count in [0, 1, 4, 31] {
        let original = commitment_fixture(count);
        let wire = original.encode_wire().unwrap();
        let pool = AllocationBudget::new(1 << 20);
        let (source, span) = source_for(&original, &pool);
        let floor = pool.reserved_bytes();
        let mut decoder = PreparedSignedBlockSignaturesDecode::new(&pool).unwrap();
        let admitted = decoder
            .decode(&source, span, norito::canonical_decode_limits(wire.len()))
            .unwrap();
        assert_eq!(admitted, original);
        assert_eq!(admitted.encode_wire().unwrap(), wire);
        let commitments = admitted.da_commitments().unwrap();
        assert!(commitments.admitted_to(&pool));
        assert!(DaCommitmentBundle::ptr_eq(
            commitments,
            decoder.retained_da_commitments(&source).unwrap().unwrap()
        ));
        let array = commitments.commitments().as_ptr();
        let aliases = commitments
            .commitments()
            .iter()
            .map(|commitment| {
                (
                    commitment.retention_class.governance_tag.0.as_ptr(),
                    commitment.acknowledgement_sig.payload().as_ptr(),
                )
            })
            .collect::<Vec<_>>();
        let reader = SharedSignedBlock::reserve(&pool)
            .unwrap()
            .initialize(admitted);
        let clone = reader.clone();
        drop(reader);
        decoder.clear_consumed();
        drop(decoder);
        assert!(clone.da_commitments().unwrap().admitted_to(&pool));
        assert_eq!(
            clone.da_commitments().unwrap().commitments().as_ptr(),
            array
        );
        assert_eq!(
            clone
                .da_commitments()
                .unwrap()
                .commitments()
                .iter()
                .map(|commitment| (
                    commitment.retention_class.governance_tag.0.as_ptr(),
                    commitment.acknowledgement_sig.payload().as_ptr()
                ))
                .collect::<Vec<_>>(),
            aliases
        );
        drop(clone);
        assert_eq!(pool.reserved_bytes(), floor);
        drop(source);
        assert_eq!(pool.reserved_bytes(), 0);
    }
}
#[test]
fn commitment_inner_enclosing_cause_preserves_original_counter_through_outer_frame_and_retry() {
    use norito::core::{
        DecodeAttemptErrorKind, DecodeLimits, DecodeResourceError, with_decode_limits_scope,
    };
    let original = commitment_fixture(2);
    let wire = original.encode_wire().unwrap();
    let pool = AllocationBudget::new(1 << 20);
    let (source, span) = source_for(&original, &pool);
    let floor = pool.reserved_bytes();
    let mut decoder = PreparedSignedBlockSignaturesDecode::new(&pool).unwrap();
    let protocol = DecodeLimits::new(1 << 20, 1 << 20, 1 << 20, 1 << 20, 64);
    let narrow = DecodeLimits::new(1, 1 << 20, 1 << 20, 1 << 20, 64);
    let error =
        with_decode_limits_scope(narrow, || decoder.decode(&source, span, protocol)).unwrap_err();
    let PreparedSignatureBlockError::Decode(PreparedDecodeError::Codec(original_cause)) = error
    else {
        panic!(
            "actual inner generated commitment sequence must retain its enclosing cause through outer workspace"
        );
    };
    assert_eq!(
        original_cause.kind(),
        DecodeAttemptErrorKind::EnclosingLimit
    );
    assert!(decoder.commitments_completed.is_none());
    let source_pointer = source.as_slice().as_ptr();
    let source_hash = Hash::new(source.as_slice());
    let retry = decoder.decode(&source, span, protocol).unwrap();
    assert_eq!(retry.encode_wire().unwrap(), wire);
    assert!(retry.da_commitments().unwrap().admitted_to(&pool));
    assert_eq!(source.as_slice().as_ptr(), source_pointer);
    assert_eq!(Hash::new(source.as_slice()), source_hash);
    assert_eq!(
        original_cause.kind(),
        DecodeAttemptErrorKind::EnclosingLimit
    );
    assert_eq!(
        original_cause.into_error().decode_resource_error(),
        Some(DecodeResourceError::SequenceLengthExceeded {
            length: 2,
            limit: 1
        })
    );
    drop(retry);
    drop(decoder);
    assert_eq!(pool.reserved_bytes(), floor);
    drop(source);
    assert_eq!(pool.reserved_bytes(), 0);
}
#[test]
fn complete_commitment_frame_rejects_changed_source_truncated_wire_and_wrong_flags() {
    let original = commitment_fixture(4);
    let wire = original.encode_wire().unwrap();
    let pool = AllocationBudget::new(1 << 20);
    let (mut source, span) = source_for(&original, &pool);
    let (copy, _) = source_for(&original, &pool);
    let mut decoder = PreparedSignedBlockSignaturesDecode::new(&pool).unwrap();
    let admitted = decoder
        .decode(&source, span, norito::canonical_decode_limits(wire.len()))
        .unwrap();
    assert!(matches!(
        decoder.retained_da_commitments(&copy),
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
    assert!(DaCommitmentBundle::ptr_eq(
        admitted.da_commitments().unwrap(),
        retry.da_commitments().unwrap()
    ));
    for end in [0, 1, wire.len() - 1] {
        let mut bad = ChargedBuffer::new(end, &pool).unwrap();
        bad.append(&wire[..end]).unwrap();
        let mut fresh = PreparedSignedBlockSignaturesDecode::new(&pool).unwrap();
        assert!(
            fresh
                .decode(
                    &bad,
                    SequenceSpan { start: 0, end },
                    norito::canonical_decode_limits(end)
                )
                .is_err()
        );
    }
    let mut wrong = wire.clone();
    wrong[1 + norito::core::Header::SIZE - 1] ^= 0x80;
    let mut bad = ChargedBuffer::new(wrong.len(), &pool).unwrap();
    bad.append(&wrong).unwrap();
    let mut fresh = PreparedSignedBlockSignaturesDecode::new(&pool).unwrap();
    assert!(
        fresh
            .decode(
                &bad,
                SequenceSpan {
                    start: 0,
                    end: wrong.len()
                },
                norito::canonical_decode_limits(wrong.len())
            )
            .is_err()
    );
}
