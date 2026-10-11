//! Actual canonical `SignedBlock` policy child walk and retained source/error owners.
use super::*;
use crate::da::commitment::{DaProofPolicy, DaProofScheme};
use iroha_model_base::topology::{DataSpaceId, LaneId};
fn policy_fixture(count: usize) -> SignedBlock {
    let mut block = fixture(0);
    let policies = DaProofPolicyBundle::new(
        (0..count)
            .map(|i| DaProofPolicy {
                lane_id: LaneId::new(u32::try_from(i).unwrap()),
                dataspace_id: DataSpaceId::new(i as u64),
                alias: if i == 0 {
                    String::new()
                } else {
                    "é漢🙂".repeat(i)
                },
                proof_scheme: DaProofScheme::MerkleSha256,
            })
            .collect(),
    );
    block
        .payload
        .header
        .set_da_proof_policies_hash(Some(iroha_crypto::HashOf::new(&policies)));
    block.payload.da_proof_policies = Some(policies);
    block
}
#[test]
fn complete_policy_child_keeps_full_canonical_frame_source_and_original_shared_readers() {
    for count in [0, 1, 4, 31] {
        let original = policy_fixture(count);
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
        let policies = admitted.da_proof_policies().unwrap();
        assert!(policies.admitted_to(&pool));
        assert!(DaProofPolicyBundle::ptr_eq(
            policies,
            decoder
                .retained_da_proof_policies(&source)
                .unwrap()
                .unwrap()
        ));
        let array = policies.policies().as_ptr();
        let aliases = policies
            .policies()
            .iter()
            .map(|policy| policy.alias.as_ptr())
            .collect::<Vec<_>>();
        let reader = SharedSignedBlock::reserve(&pool)
            .unwrap()
            .initialize(admitted);
        let clone = reader.clone();
        drop(reader);
        decoder.clear_consumed();
        drop(decoder);
        assert!(clone.da_proof_policies().unwrap().admitted_to(&pool));
        assert_eq!(
            clone.da_proof_policies().unwrap().policies().as_ptr(),
            array
        );
        assert_eq!(
            clone
                .da_proof_policies()
                .unwrap()
                .policies()
                .iter()
                .map(|policy| policy.alias.as_ptr())
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
fn policy_inner_enclosing_cause_preserves_original_counter_through_outer_frame_and_retry() {
    use norito::core::{
        DecodeAttemptErrorKind, DecodeLimits, DecodeResourceError, with_decode_limits_scope,
    };
    let original = policy_fixture(2);
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
            "actual inner generated policy sequence must retain its enclosing cause through outer workspace"
        );
    };
    assert_eq!(
        original_cause.kind(),
        DecodeAttemptErrorKind::EnclosingLimit
    );
    assert!(decoder.policy_completed.is_none());
    let source_pointer = source.as_slice().as_ptr();
    let source_hash = Hash::new(source.as_slice());
    let retry = decoder.decode(&source, span, protocol).unwrap();
    assert_eq!(retry.encode_wire().unwrap(), wire);
    assert!(retry.da_proof_policies().unwrap().admitted_to(&pool));
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
fn complete_policy_frame_rejects_changed_source_truncated_wire_and_wrong_flags() {
    let original = policy_fixture(4);
    let wire = original.encode_wire().unwrap();
    let pool = AllocationBudget::new(1 << 20);
    let (mut source, span) = source_for(&original, &pool);
    let (copy, _) = source_for(&original, &pool);
    let mut decoder = PreparedSignedBlockSignaturesDecode::new(&pool).unwrap();
    let admitted = decoder
        .decode(&source, span, norito::canonical_decode_limits(wire.len()))
        .unwrap();
    assert!(matches!(
        decoder.retained_da_proof_policies(&copy),
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
    assert!(DaProofPolicyBundle::ptr_eq(
        admitted.da_proof_policies().unwrap(),
        retry.da_proof_policies().unwrap()
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
