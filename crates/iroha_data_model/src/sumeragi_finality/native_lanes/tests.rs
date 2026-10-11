//! Actual sparse-tree, bounded codec and original-pool refusal regressions.

use super::*;
use crate::block::consensus::ExecKv;
use iroha_crypto::HashOf;

fn fixture() -> (NetworkId, ExecWitness, Hash) {
    let network = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
        b"native context proof",
    )));
    let commitment =
        SumeragiLaneStateCommitment::from_state(network, 2, &SumeragiLaneState::default()).unwrap();
    let mut writes = (0_u32..37)
        .map(|index| ExecKv {
            key: index.to_le_bytes().to_vec(),
            value: (index * 19).to_le_bytes().to_vec(),
        })
        .collect::<Vec<_>>();
    writes.push(ExecKv {
        key: writes[3].key.clone(),
        value: b"last exact ordinary write wins".to_vec(),
    });
    writes.push(ExecKv {
        key: SUMERAGI_LANE_STATE_WITNESS_KEY.to_vec(),
        value: norito::encode_canonical(&commitment).unwrap(),
    });
    let witness = ExecWitness {
        writes,
        ..ExecWitness::default()
    };
    let root = NativeLaneStateProof::from_witness(&witness, &AllocationBudget::new(100_000))
        .unwrap()
        .root()
        .unwrap();
    (network, witness, root)
}

#[test]
fn original_funded_proof_authenticates_absence_and_rejects_changed_path() {
    let (network, witness, root) = fixture();
    let budget = AllocationBudget::new(2 * witness.writes.len() * std::mem::size_of::<Node>());
    let proof = NativeLaneStateProof::from_witness(&witness, &budget).unwrap();
    assert_eq!(
        budget.reserved_bytes(),
        0,
        "scratch has no retained heap owner"
    );
    assert!(proof.verify(network, 2, root));
    assert!(
        proof
            .matches_state(network, 2, &SumeragiLaneState::default())
            .unwrap()
    );
    assert!(!proof.verify(network, 3, root));
    assert!(!proof.verify(network, 2, Hash::new(b"foreign root")));
    let foreign =
        NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(b"foreign")));
    assert!(!proof.verify(foreign, 2, root));
    let mut changed = proof.clone();
    changed.siblings[3][31] = Hash::new(b"false sibling");
    assert!(!changed.verify(network, 2, root));
    let bytes = norito::encode_canonical(&proof).unwrap();
    assert!(bytes.len() < 12 * 1024);
    let decoded: NativeLaneStateProof = norito::decode_canonical_with_limits(
        &bytes,
        norito::DecodeLimits::new(96, 12 * 1024, 16384, 64 * 1024, 12),
    )
    .unwrap();
    assert_eq!(decoded, proof);
    for level in [0, 255] {
        let mut changed = bytes.clone();
        changed.truncate(changed.len() - level - 1);
        assert!(
            norito::decode_canonical_with_limits::<NativeLaneStateProof>(
                &changed,
                norito::canonical_decode_limits(changed.len())
            )
            .is_err()
        );
    }
}

#[test]
fn actual_original_pool_capacity_refusal_preserves_witness_and_retries_without_new_pool() {
    let (network, witness, root) = fixture();
    let demand = 2 * witness.writes.len() * std::mem::size_of::<Node>();
    let budget = AllocationBudget::new(demand);
    let occupied = ChargedBuffer::<u8>::new(1, &budget).unwrap();
    let writes = witness.writes.as_ptr();
    let first = witness.writes[0].key.as_ptr();
    let error = NativeLaneStateProof::from_witness(&witness, &budget).unwrap_err();
    assert!(error.is_local_refusal());
    assert_eq!(budget.reserved_bytes(), 1);
    assert_eq!(witness.writes.as_ptr(), writes);
    assert_eq!(witness.writes[0].key.as_ptr(), first);
    drop(occupied);
    let proof = NativeLaneStateProof::from_witness(&witness, &budget.clone()).unwrap();
    assert!(proof.verify(network, 2, root));
    assert_eq!(budget.reserved_bytes(), 0);
    let inadequate = AllocationBudget::new(demand - 1);
    assert!(
        !NativeLaneStateProof::from_witness(&witness, &inadequate)
            .unwrap_err()
            .is_local_refusal()
    );
    assert_eq!(inadequate.reserved_bytes(), 0);
}

#[test]
fn malformed_missing_duplicate_or_noncanonical_write_is_not_resource_refusal() {
    let (_, witness, _) = fixture();
    let budget = AllocationBudget::new(100_000);
    for mutation in 0..4 {
        let mut bad = witness.clone();
        match mutation {
            0 => {
                bad.writes.pop();
            }
            1 => bad.writes.push(bad.writes.last().unwrap().clone()),
            2 => bad.writes.last_mut().unwrap().value.push(0),
            3 => bad
                .writes
                .last_mut()
                .unwrap()
                .value
                .resize(COMMITMENT_BYTES + 1, 0),
            _ => unreachable!(),
        }
        assert!(
            !NativeLaneStateProof::from_witness(&bad, &budget)
                .unwrap_err()
                .is_local_refusal()
        );
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

#[test]
fn single_fixed_write_and_reordered_distinct_writes_use_the_same_tree_rules() {
    let (network, mut witness, _) = fixture();
    witness
        .writes
        .retain(|write| write.key == SUMERAGI_LANE_STATE_WITNESS_KEY);
    let root = NativeLaneStateProof::from_witness(&witness, &AllocationBudget::new(100_000))
        .unwrap()
        .root()
        .unwrap();
    let budget = AllocationBudget::new(100_000);
    assert!(
        NativeLaneStateProof::from_witness(&witness, &budget)
            .unwrap()
            .verify(network, 2, root)
    );
    let (network, mut witness, root) = fixture();
    // Keep the original duplicate's last-write semantics, then reorder distinct keys.
    witness.writes.remove(3);
    witness.writes.reverse();
    assert!(
        NativeLaneStateProof::from_witness(&witness, &budget)
            .unwrap()
            .verify(network, 2, root)
    );
}

#[test]
fn exact_encoding_comparison_is_not_a_substitute_for_native_root_authentication() {
    let (network, witness, root) = fixture();
    let proof =
        NativeLaneStateProof::from_witness(&witness, &AllocationBudget::new(100_000)).unwrap();
    let empty = SumeragiLaneState::default();
    assert!(proof.matches_state_encoding(network, 2, &empty).unwrap());
    assert!(!proof.matches_state_encoding(network, 3, &empty).unwrap());
    let foreign = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
        b"foreign archive network",
    )));
    assert!(!proof.matches_state_encoding(foreign, 2, &empty).unwrap());
    let mut altered_path = proof;
    altered_path.siblings[0][0] = Hash::new(b"uncertified path");
    assert!(
        altered_path
            .matches_state_encoding(network, 2, &empty)
            .unwrap()
    );
    assert!(
        !altered_path.verify(network, 2, root),
        "exact context bytes alone do not confer finality"
    );
}

#[test]
fn borrowed_lane_equality_never_authenticates_a_changed_native_result_or_path() {
    let (network, witness, root) = fixture();
    let proof =
        NativeLaneStateProof::from_witness(&witness, &AllocationBudget::new(100_000)).unwrap();
    let frame = norito::encode_canonical(&SumeragiLaneState::default()).unwrap();
    let payload = norito::core::from_bytes_view(&frame).unwrap().as_bytes();
    assert!(proof.verify(network, 2, root));
    assert!(proof.matches_state_payload(network, 2, payload).unwrap());
    assert!(!proof.matches_state_payload(network, 3, payload).unwrap());
    let foreign = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
        b"foreign receipt",
    )));
    assert!(!proof.matches_state_payload(foreign, 2, payload).unwrap());
    assert!(!proof.verify(network, 2, Hash::new(b"other native result root")));
    let mut changed_path = proof.clone();
    changed_path.siblings[0][0] = Hash::new(b"uncertified path");
    assert!(
        changed_path
            .matches_state_payload(network, 2, payload)
            .unwrap()
    );
    assert!(
        !changed_path.verify(network, 2, root),
        "raw equality cannot authenticate its own path"
    );
    let mut changed_value = payload.to_vec();
    changed_value[0] ^= 1;
    assert!(
        !proof
            .matches_state_payload(network, 2, &changed_value)
            .unwrap()
    );
}

#[test]
fn original_commitment_decoder_refusal_preserves_origin_after_scope_and_retries() {
    let (network, witness, root) = fixture();
    let budget =
        AllocationBudget::new(NativeLaneStateProof::scratch_bytes(witness.writes.len()).unwrap());
    let target = witness
        .writes
        .iter()
        .find(|write| write.key == SUMERAGI_LANE_STATE_WITNESS_KEY)
        .unwrap();
    let defaults = norito::canonical_decode_limits(target.value.len());
    let limits = norito::DecodeLimits::new(
        defaults.max_sequence_elements(),
        defaults.max_field_bytes(),
        defaults.max_total_elements(),
        defaults.max_total_allocated_bytes(),
        0,
    );
    let writes = witness.writes.as_ptr();
    let pointer = target.value.as_ptr();
    let source = HashOf::new(&witness);
    let refused = norito::with_decode_limits_scope(limits, || {
        NativeLaneStateProof::from_witness(&witness, &budget)
    })
    .unwrap_err();
    let NativeLaneStateProofError::Decode(original) = &refused else {
        panic!("the actual canonical commitment must retain its captured decoder error: {refused}")
    };
    assert_eq!(
        original.kind(),
        norito::core::DecodeAttemptErrorKind::EnclosingLimit
    );
    assert!(matches!(
        std::error::Error::source(original)
            .unwrap()
            .downcast_ref::<norito::Error>()
            .unwrap()
            .decode_resource_error(),
        Some(norito::core::DecodeResourceError::NestingDepthExceeded {
            limit: 0,
            context: "decode budget",
            ..
        })
    ));
    assert!(
        refused.is_local_refusal(),
        "caller origin must survive scope retirement"
    );
    assert_eq!(
        budget.reserved_bytes(),
        0,
        "commitment decode refused before scratch admission"
    );
    assert_eq!(witness.writes.as_ptr(), writes);
    assert_eq!(target.value.as_ptr(), pointer);
    assert_eq!(HashOf::new(&witness), source);
    assert!(
        NativeLaneStateProof::from_witness(&witness, &budget)
            .unwrap()
            .verify(network, 2, root)
    );
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn malformed_original_commitment_keeps_terminal_decoder_origin_under_wider_caller() {
    let (_, mut witness, _) = fixture();
    let budget =
        AllocationBudget::new(NativeLaneStateProof::scratch_bytes(witness.writes.len()).unwrap());
    witness
        .writes
        .iter_mut()
        .find(|write| write.key == SUMERAGI_LANE_STATE_WITNESS_KEY)
        .unwrap()
        .value
        .pop()
        .unwrap();
    let refused = norito::with_decode_limits_scope(
        norito::DecodeLimits::new(
            usize::MAX,
            usize::MAX,
            usize::MAX,
            usize::MAX,
            norito::core::MAX_VALUE_NESTING_DEPTH,
        ),
        || NativeLaneStateProof::from_witness(&witness, &budget),
    )
    .unwrap_err();
    let NativeLaneStateProofError::Decode(original) = &refused else {
        panic!("truncated genuine commitment must preserve its terminal decoder source: {refused}")
    };
    assert_eq!(
        original.kind(),
        norito::core::DecodeAttemptErrorKind::Invalid
    );
    assert!(
        std::error::Error::source(original)
            .unwrap()
            .downcast_ref::<norito::Error>()
            .unwrap()
            .decode_resource_error()
            .is_none()
    );
    assert!(!refused.is_local_refusal());
    assert_eq!(budget.reserved_bytes(), 0);
}
