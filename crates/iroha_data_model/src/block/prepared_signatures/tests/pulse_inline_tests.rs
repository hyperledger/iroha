//! Complete canonical block pulse fields, original source refusal and counter custody.
use super::*;
use crate::{
    NetworkId,
    consensus::{
        FinalizedGlobalThresholdBeaconPulseV1, GlobalThresholdBeaconChainAnchorV1,
        GlobalThresholdBeaconPulseContextV1,
    },
};
fn pulse_fixture() -> FinalizedGlobalThresholdBeaconPulseV1 {
    // Codec/source custody only: this is not an authenticated DKG/native pulse.
    FinalizedGlobalThresholdBeaconPulseV1 {
        version: 1,
        network_id: NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
            Hash::new(b"prepared inline pulse genesis"),
        )),
        session_id: [2; 32],
        roster_hash: [3; 32],
        transcript_hash: [4; 32],
        context: GlobalThresholdBeaconPulseContextV1 {
            instance: [5; 32],
            epoch: 7,
            epoch_context_id: [6; 32],
            parent_consensus_hash: [7; 32],
            parent_result: [8; 32],
        },
        height: 9,
        round: 0,
        finalized_chain_anchor: GlobalThresholdBeaconChainAnchorV1 {
            height: 8,
            block_hash: iroha_crypto::HashOf::from_untyped_unchecked(Hash::new(
                b"prepared inline pulse parent",
            )),
        },
        signature: [11; 48],
        seed: [12; 32],
        pulse_id: [13; 32],
    }
}
fn pulse_block(count: usize, pulse: Option<&FinalizedGlobalThresholdBeaconPulseV1>) -> SignedBlock {
    let mut original = fixture(count);
    original.set_global_beacon_pulse(pulse.copied());
    original.validate_proposal_commitments().unwrap();
    original
}

#[test]
fn complete_inline_pulse_child_keeps_original_canonical_block_and_shared_static_owner() {
    let pulse = pulse_fixture();
    for count in [0, 4, 31] {
        for value in [None, Some(pulse)] {
            let original = pulse_block(count, value.as_ref());
            let wire = original.encode_wire().unwrap();
            let ordinary = crate::block::decode_framed_signed_block(&wire).unwrap();
            assert_eq!(ordinary, original);
            assert_eq!(
                ordinary.header().global_beacon_pulse_hash(),
                value.as_ref().map(iroha_crypto::HashOf::new)
            );
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
            assert_eq!(admitted.global_beacon_pulse(), value.as_ref());
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
            assert_eq!(retry.global_beacon_pulse(), value.as_ref());
            drop(retry);
            let held = SharedSignedBlock::reserve(&pool)
                .unwrap()
                .initialize(admitted);
            let pulse_address = held.global_beacon_pulse().map(std::ptr::from_ref);
            let clone = held.clone();
            assert_eq!(
                clone.global_beacon_pulse().map(std::ptr::from_ref),
                pulse_address
            );
            drop(held);
            decoder.clear_consumed();
            drop(decoder);
            assert_eq!(
                clone.global_beacon_pulse().map(std::ptr::from_ref),
                pulse_address
            );
            assert_eq!(clone.global_beacon_pulse(), value.as_ref());
            assert_eq!(clone.encode_wire().unwrap(), wire);
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
fn pulse_block_original_signature_enclosing_cause_keeps_same_source_and_retry() {
    use norito::core::{
        DecodeAttemptErrorKind, DecodeLimits, DecodeResourceError, with_decode_limits_scope,
    };
    let pulse = pulse_fixture();
    let original = pulse_block(4, Some(&pulse));
    let wire = original.encode_wire().unwrap();
    let pool = AllocationBudget::new(1 << 20);
    let (source, span) = source_for(&original, &pool);
    let floor = pool.reserved_bytes();
    let pointer = source.as_slice().as_ptr();
    let hash = Hash::new(source.as_slice());
    let mut decoder = PreparedSignedBlockSignaturesDecode::new(&pool).unwrap();
    let protocol = DecodeLimits::new(1 << 20, 1 << 20, 1 << 20, 1 << 20, 64);
    let narrow = DecodeLimits::new(0, 1 << 20, 1 << 20, 1 << 20, 64);
    let error =
        with_decode_limits_scope(narrow, || decoder.decode(&source, span, protocol)).unwrap_err();
    let PreparedSignatureBlockError::Decode(PreparedDecodeError::Codec(cause)) = error else {
        panic!(
            "original signature sequence must preserve its enclosing reader through the complete block field walk"
        );
    };
    assert_eq!(cause.kind(), DecodeAttemptErrorKind::EnclosingLimit);
    assert!(decoder.retained_signatures(&source).unwrap().is_none());
    let retry = decoder.decode(&source, span, protocol).unwrap();
    assert_eq!(retry.global_beacon_pulse(), Some(&pulse));
    assert_eq!(retry.encode_wire().unwrap(), wire);
    assert!(retry.signatures.admitted_to(&pool));
    assert_eq!(source.as_slice().as_ptr(), pointer);
    assert_eq!(Hash::new(source.as_slice()), hash);
    assert_eq!(cause.kind(), DecodeAttemptErrorKind::EnclosingLimit);
    assert_eq!(
        cause.into_error().decode_resource_error(),
        Some(DecodeResourceError::SequenceLengthExceeded {
            length: 4,
            limit: 0
        })
    );
    drop(retry);
    drop(decoder);
    assert_eq!(pool.reserved_bytes(), floor);
    drop(source);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn complete_pulse_block_rejects_foreign_changed_truncated_and_wrong_flags_sources_with_original_causes()
 {
    let pulse = pulse_fixture();
    let original = pulse_block(4, Some(&pulse));
    let wire = original.encode_wire().unwrap();
    let pool = AllocationBudget::new(1 << 20);
    let (mut source, span) = source_for(&original, &pool);
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
    // Alter the original initialized bytes outside the selected frame: complete
    // source identity still owns them, so equality of selected wire is insufficient.
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
    assert_eq!(retry.global_beacon_pulse(), admitted.global_beacon_pulse());
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
    drop(source);
    assert_eq!(pool.reserved_bytes(), 0);
}
