//! Resource refusal preserves authentic evidence and the original capture for retry.
use super::*;
use norito::core::{DecodeLimits, with_decode_limits_scope};

#[test]
fn native_decode_refusal_refunds_capture_without_blaming_original_proof() {
    let _guard = crossbeam_epoch::pin();
    let mut chain = super::tests::chain();
    chain.commit(Vec::new());
    let proof = Evidence::from_native(&super::tests::conflict(&chain, 2)).unwrap();
    let original = proof.native_frame().to_vec();
    let state = chain.state();
    let generation = state.state_view_generation();
    let tip = state.view().native_execution_tip();
    let budget = state.evidence_preparation_budget();
    let baseline = budget.reserved_bytes();
    let limits = DecodeLimits::new(usize::MAX, 1, usize::MAX, usize::MAX, usize::MAX);
    let refusal = with_decode_limits_scope(limits, || {
        admission::prepare_admissions(state, generation, 3, std::slice::from_ref(&proof))
    })
    .err()
    .expect("the native proof exceeds the active field ceiling");
    assert!(
        matches!(refusal, EvidenceAdmissionError::Preparation(_)),
        "{refusal:?}"
    );
    assert!(admission::retryable(&refusal));
    assert_eq!(
        budget.reserved_bytes(),
        baseline,
        "failed capture refunds partial backing"
    );
    assert_eq!(proof.native_frame(), original);
    assert_eq!(state.state_view_generation(), generation);
    assert_eq!(state.view().native_execution_tip(), tip);
    let admitted =
        admission::prepare_admissions(state, generation, 3, std::slice::from_ref(&proof)).unwrap();
    assert!(admitted.belongs_to(budget));
    assert_eq!(admitted.as_slice()[0].key(), evidence_key(&proof));
    drop(admitted);
    assert_eq!(budget.reserved_bytes(), baseline);
}

#[test]
fn persisted_root_decode_refusal_retains_original_validation_cut_for_retry() {
    let _guard = crossbeam_epoch::pin();
    let mut chain = super::tests::chain();
    chain.commit(Vec::new());
    let native = super::tests::conflict(&chain, 2);
    let proof = Evidence::from_native(&native).unwrap();
    let key = evidence_key(&proof);
    observe(chain.state(), &native).unwrap();
    chain.commit(Vec::new());
    let state = chain.state();
    let original = state
        .view()
        .world()
        .consensus_evidence()
        .get(&key)
        .unwrap()
        .clone();
    let generation = state.state_view_generation();
    let tip = state.view().native_execution_tip();
    let baseline = state.evidence_preparation_budget().reserved_bytes();
    let limits = DecodeLimits::new(usize::MAX, 1, usize::MAX, usize::MAX, usize::MAX);
    for _ in 0..2 {
        let refusal = with_decode_limits_scope(limits, || validate_persisted_records(state))
            .expect_err("persisted proof exceeds the active field ceiling");
        assert!(
            matches!(refusal, EvidenceAdmissionError::Preparation(_)),
            "{refusal:?}"
        );
        assert!(admission::retryable(&refusal));
        assert!(state.native_evidence_admission.lock().restore.is_some());
        assert_eq!(state.state_view_generation(), generation);
        assert_eq!(state.view().native_execution_tip(), tip);
        assert_eq!(
            state.view().world().consensus_evidence().get(&key),
            Some(&original)
        );
    }
    validate_persisted_records(state).unwrap();
    assert!(state.native_evidence_admission.lock().restore.is_none());
    assert_eq!(
        state.evidence_preparation_budget().reserved_bytes(),
        baseline
    );
}

#[test]
fn codec_refusal_adapter_preserves_all_resource_fields_and_rejects_impostors() {
    use iroha_sumeragi::message::CodecError;
    use norito::core::DecodeResourceError as Resource;
    let resources = [
        Resource::ArchiveLengthExceeded {
            length: 101,
            limit: 100,
        },
        Resource::SequenceLengthExceeded {
            length: 51,
            limit: 50,
        },
        Resource::FieldLengthExceeded {
            length: 31,
            limit: 30,
        },
        Resource::TotalElementsExceeded {
            attempted: 21,
            limit: 20,
        },
        Resource::TotalAllocationExceeded {
            attempted: 11,
            limit: 10,
        },
        Resource::AllocationFailed { bytes: 2048 },
        Resource::NestingDepthExceeded {
            depth: 5,
            limit: 4,
            context: "original proof",
        },
    ];
    for resource in resources {
        let error = EvidenceAdmissionError::from(CodecError::Resource(resource));
        assert!(matches!(&error, EvidenceAdmissionError::Preparation(
            EvidencePreparationError::DecodeResource(actual)
        ) if *actual == resource));
        assert!(admission::retryable(&error));
        let preparation = EvidencePreparationError::DecodeResource(resource);
        assert_eq!(preparation.clone(), preparation);
        assert!(preparation.release_wait().is_none());
    }
    for error in [
        CodecError::Norito("failed to allocate 2048 bytes while decoding".into()),
        CodecError::TooLarge { len: 101, max: 100 },
        CodecError::Limit("canonical proof bound"),
        CodecError::from(norito::Error::ChecksumMismatch),
        CodecError::from(norito::Error::Io(std::io::ErrorKind::OutOfMemory.into())),
    ] {
        let error = EvidenceAdmissionError::from(error);
        assert!(matches!(error, EvidenceAdmissionError::Invalid(_)));
        assert!(!admission::retryable(&error));
    }
}
