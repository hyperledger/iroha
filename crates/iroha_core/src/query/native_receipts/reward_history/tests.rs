//! Original committed archive availability, integrity and refusal controls.

use super::*;
use crate::{
    state::{NativeExecutionProjectionV1, World},
    sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
};
use iroha_allocation::{AllocationBudget, ChargedBuffer};
use iroha_crypto::HashOf;
use iroha_data_model::{
    block::consensus::ExecKv, sumeragi_finality::SUMERAGI_LANE_STATE_WITNESS_KEY,
};

fn committed_chain() -> CertifiedTestChain {
    let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
    chain.commit(Vec::new());
    chain
}

fn original_path(chain: &CertifiedTestChain) -> std::path::PathBuf {
    chain
        .kura()
        .store_root()
        .join("native-contexts")
        .join(format!(
            "{:020}-{}.nrt",
            2,
            hex::encode(chain.committed(2).block_hash().as_ref()),
        ))
}

#[test]
fn committed_fee_archive_preserves_original_corpus_and_rejects_absent_exposure() {
    let chain = committed_chain();
    let view = chain.state().view();
    let proof = committed_fee_evidence(&view, 2).unwrap();
    assert!(
        proof.verify(
            chain
                .committed(2)
                .commitment()
                .execution
                .ordinary_writes_root
        )
    );
    assert_eq!(
        proof
            .snapshot_witness
            .commitment()
            .unwrap()
            .evaluated_height,
        2
    );
    let key = "reward_history/ExposureArchive/absent".parse().unwrap();
    assert!(matches!(
        committed_reward_exposure(&view, 2, &key, Hash::new(b"absent")),
        Err(ExecutionAttemptError::Rejected(reason)) if reason.contains("source is absent")
    ));
}

#[test]
fn committed_reward_archive_missing_corrupt_and_changed_root_defer_without_fabrication() {
    let chain = committed_chain();
    let path = original_path(&chain);
    let original = std::fs::read(&path).unwrap();
    let hidden = path.with_extension("retained-test-original");
    std::fs::rename(&path, &hidden).unwrap();
    let missing = committed_fee_evidence(&chain.state().view(), 2);
    std::fs::rename(&hidden, &path).unwrap();
    assert!(
        matches!(missing, Err(ExecutionAttemptError::Deferred(reason))
        if reason.reason() == ExecutionDeferral::CanonicalHistoryUnavailable)
    );

    std::fs::write(&path, b"invalid canonical archive").unwrap();
    let corrupt = committed_fee_evidence(&chain.state().view(), 2);
    std::fs::write(&path, &original).unwrap();
    assert!(
        matches!(corrupt, Err(ExecutionAttemptError::Deferred(reason))
        if reason.reason() == ExecutionDeferral::CanonicalHistoryUnavailable)
    );

    let mut projection: NativeExecutionProjectionV1 = norito::decode_canonical(&original).unwrap();
    projection.ordinary_writes.push(ExecKv {
        key: b"unexecuted-reward-source".to_vec(),
        value: vec![1],
    });
    std::fs::write(&path, norito::to_bytes(&projection).unwrap()).unwrap();
    let changed = committed_fee_evidence(&chain.state().view(), 2);
    std::fs::write(&path, &original).unwrap();
    assert!(
        matches!(changed, Err(ExecutionAttemptError::Deferred(reason))
        if reason.reason() == ExecutionDeferral::CanonicalHistoryUnavailable)
    );
    committed_fee_evidence(&chain.state().view(), 2).unwrap();
}

#[test]
fn reward_archive_capacity_preserves_original_pool_refusal() {
    let budget = AllocationBudget::new(32);
    let held = budget.try_reserve_bytes(32).unwrap();
    let expected = budget.try_reserve_bytes(1).unwrap_err();
    for via_storage in [false, true] {
        let actual = ChargedBuffer::<u8>::new(1, &budget)
            .err()
            .expect("zero-capacity pool refuses the original buffer");
        let original = if via_storage {
            NativeContextArchiveError::Storage(crate::kura::Error::NativeFrameAllocation(actual))
        } else {
            NativeContextArchiveError::Allocation(actual)
        };
        let error = archive_error(original);
        assert!(matches!(error, ExecutionAttemptError::Deferred(reason)
            if reason.allocation_refusal() == Some(&expected)));
        assert_eq!(budget.reserved_bytes(), 32);
    }
    for via_archive in [false, true] {
        let actual = ChargedBuffer::<u8>::new(1, &budget)
            .err()
            .expect("occupied original pool refuses proof scratch");
        let proof = NativeLaneStateProofError::Scratch(actual);
        let error = if via_archive {
            archive_error(NativeContextArchiveError::Proof(proof))
        } else {
            lane_error(proof)
        };
        assert!(matches!(error, ExecutionAttemptError::Deferred(reason)
            if reason.allocation_refusal() == Some(&expected)));
        assert_eq!(budget.reserved_bytes(), 32);
    }
    drop(held);
    ChargedBuffer::<u8>::new(1, &budget).unwrap();
}

#[test]
fn reward_archive_proof_decoder_preserves_retired_scope_and_refuses_corrupt_commitment() {
    let chain = committed_chain();
    let original = std::fs::read(original_path(&chain)).unwrap();
    let projection: NativeExecutionProjectionV1 = norito::decode_canonical(&original).unwrap();
    let mut witness = ExecWitness {
        writes: projection.ordinary_writes,
        ..ExecWitness::default()
    };
    let budget =
        AllocationBudget::new(NativeLaneStateProof::scratch_bytes(witness.writes.len()).unwrap());
    let commitment = witness
        .writes
        .iter()
        .find(|write| write.key == SUMERAGI_LANE_STATE_WITNESS_KEY)
        .unwrap();
    let pointer = commitment.value.as_ptr();
    let source = HashOf::new(&witness);
    let defaults = norito::canonical_decode_limits(commitment.value.len());
    let limits = norito::DecodeLimits::new(
        defaults.max_sequence_elements(),
        defaults.max_field_bytes(),
        defaults.max_total_elements(),
        defaults.max_total_allocated_bytes(),
        0,
    );
    for via_archive in [false, true] {
        let proof = norito::with_decode_limits_scope(limits, || {
            NativeLaneStateProof::from_witness(&witness, &budget)
        })
        .unwrap_err();
        assert!(matches!(&proof, NativeLaneStateProofError::Decode(error)
            if error.kind() == norito::core::DecodeAttemptErrorKind::EnclosingLimit));
        let error = if via_archive {
            archive_error(NativeContextArchiveError::Proof(proof))
        } else {
            lane_error(proof)
        };
        assert!(matches!(error, ExecutionAttemptError::Deferred(reason)
            if reason.reason() == ExecutionDeferral::ActiveMemoryCapacity
                && reason.allocation_refusal().is_none()));
        assert_eq!(commitment.value.as_ptr(), pointer);
        assert_eq!(HashOf::new(&witness), source);
        assert_eq!(budget.reserved_bytes(), 0);
    }
    assert_eq!(
        NativeLaneStateProof::from_witness(&witness, &budget).unwrap(),
        chain.committed(2).commitment().native_lanes
    );
    assert_eq!(budget.reserved_bytes(), 0);

    witness
        .writes
        .iter_mut()
        .find(|write| write.key == SUMERAGI_LANE_STATE_WITNESS_KEY)
        .unwrap()
        .value
        .pop()
        .unwrap();
    for via_archive in [false, true] {
        let proof = NativeLaneStateProof::from_witness(&witness, &budget).unwrap_err();
        assert!(matches!(&proof, NativeLaneStateProofError::Decode(error)
            if error.kind() == norito::core::DecodeAttemptErrorKind::Invalid));
        assert!(!proof.is_local_refusal());
        let error = if via_archive {
            archive_error(NativeContextArchiveError::Proof(proof))
        } else {
            lane_error(proof)
        };
        assert!(matches!(error, ExecutionAttemptError::Deferred(reason)
            if reason.reason() == ExecutionDeferral::CanonicalHistoryUnavailable
                && reason.allocation_refusal().is_none()));
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

#[test]
fn reward_archive_storage_retains_original_decode_and_allocator_causes() {
    use crate::kura::Error as KuraError;
    let bytes = norito::encode_canonical(&vec![19_u8; 32]).unwrap();
    let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX);
    let attempt = norito::with_decode_limits_scope(limits, || {
        norito::decode_canonical_for_admission::<Vec<u8>>(
            &bytes,
            norito::canonical_decode_limits(bytes.len()),
        )
    })
    .unwrap_err();
    let expected = attempt.local_refusal().unwrap();
    let error = archive_error(NativeContextArchiveError::Storage(KuraError::CodecAttempt(
        attempt,
    )));
    assert!(matches!(error, ExecutionAttemptError::Deferred(reason)
        if reason.reason() == ExecutionDeferral::ActiveMemoryCapacity
            && reason.decode_refusal() == Some(&expected)
            && reason.allocation_refusal().is_none()));

    // Transport the existing allocator report; this does not inject a physical failure.
    let error = archive_error(NativeContextArchiveError::Storage(
        KuraError::NativeFrameAllocation(ChargedBufferError::Allocator {
            requested_bytes: 73,
        }),
    ));
    let ExecutionAttemptError::Deferred(reason) = error else {
        panic!("original allocator refusal must defer");
    };
    assert_eq!(reason.reason(), ExecutionDeferral::AllocationUnavailable);
    assert!(matches!(
        reason.allocator_refusal().unwrap().buffer_error(),
        Some(ChargedBufferError::Allocator {
            requested_bytes: 73
        })
    ));
    assert!(reason.allocation_refusal().is_none());

    let protocol = norito::decode_canonical_for_admission::<Vec<u8>>(&bytes, limits).unwrap_err();
    assert!(protocol.local_refusal().is_none());
    for original in [
        KuraError::CodecAttempt(protocol),
        KuraError::NoritoFrame(norito::Error::InvalidMagic),
        KuraError::CanonicalBlockWireMismatch { height: 2 },
        KuraError::IO(
            std::io::ErrorKind::NotFound.into(),
            "original-archive".into(),
        ),
        KuraError::FastpqArtifactQuota {
            stable_count: 1,
            retained_bytes: 8,
            incoming_bytes: 1,
            maximum_records: 1,
            maximum_bytes: 8,
        },
    ] {
        let error = archive_error(NativeContextArchiveError::Storage(original));
        assert!(matches!(error, ExecutionAttemptError::Deferred(reason)
            if reason.reason() == ExecutionDeferral::CanonicalHistoryUnavailable
                && reason.allocation_refusal().is_none()
                && reason.allocator_refusal().is_none()
                && reason.decode_refusal().is_none()));
    }
}
