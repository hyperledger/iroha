//! Actual signed evidence decoder input and original charged capture retirement.
use super::*;
use std::cell::Cell;

#[test]
fn signed_evidence_decoder_reads_charged_capture_through_last_record_reader() {
    let _epoch = crossbeam_epoch::pin();
    let mut chain = super::super::tests::chain();
    chain.commit(Vec::new());
    let proof = Evidence::from_native(&super::super::tests::conflict(&chain, 2)).unwrap();
    let state = chain.state();
    let view = state.view();
    let generation = state.state_view_generation();
    let tip = view.native_execution_tip();
    let pool = state.evidence_preparation_budget();
    let floor = pool.reserved_bytes();
    let hash = Hash::new(proof.native_frame());
    let source = Cell::new(None);
    let mut read = AdmissionRead::capture_observing(
        state,
        &view,
        generation,
        3,
        std::slice::from_ref(&proof),
        |frame| {
            assert!(frame.belongs_to(pool));
            assert_eq!(frame.as_slice(), proof.native_frame());
            assert_eq!(Hash::new(frame.as_slice()), hash);
            assert_ne!(
                frame.as_slice().as_ptr(),
                proof.native_frame().as_ptr(),
                "decoder must read charged capture, not offered proof"
            );
            assert!(source.replace(Some(frame.as_slice().as_ptr())).is_none());
        },
    )
    .unwrap();
    let pointer = source.get().expect("actual decoder input was observed");
    assert_eq!(
        read.candidates.as_slice()[0]
            .frame
            .as_ref()
            .unwrap()
            .as_slice()
            .as_ptr(),
        pointer
    );
    assert!(read.matches(generation, 3, std::slice::from_ref(&proof)));
    assert_eq!(state.state_view_generation(), generation);
    assert_eq!(view.native_execution_tip(), tip);
    read.complete().unwrap();
    let admitted = read.finish().unwrap();
    assert_eq!(
        admitted.as_slice()[0].native_frame().unwrap().as_ptr(),
        pointer
    );
    assert_eq!(admitted.as_slice()[0].attribution().height, 2);
    assert!(admitted.as_slice()[0].attribution().safety_violation);
    assert_eq!(
        admitted.as_slice()[0]
            .attribution()
            .offenders
            .iter()
            .map(|offender| offender.signer)
            .collect::<Vec<_>>(),
        [1, 2]
    );
    let record = admitted.as_slice()[0].record(&proof, 3, 0, 3_000).unwrap();
    let last = record.clone();
    drop(admitted);
    drop(record);
    assert_eq!(
        last.native_evidence().unwrap().native_frame().as_ptr(),
        pointer
    );
    assert_eq!(
        last.native_evidence().unwrap().native_frame(),
        proof.native_frame()
    );
    assert!(
        pool.reserved_bytes() > floor,
        "captured source stays funded with final record reader"
    );
    drop(last);
    assert_eq!(pool.reserved_bytes(), floor);
    assert_eq!(state.state_view_generation(), generation);
    assert_eq!(view.native_execution_tip(), tip);
}

#[test]
fn charged_evidence_decode_refusal_retires_capture_and_retries_unchanged_signed_source() {
    let _epoch = crossbeam_epoch::pin();
    let mut chain = super::super::tests::chain();
    chain.commit(Vec::new());
    let proof = Evidence::from_native(&super::super::tests::conflict(&chain, 2)).unwrap();
    let state = chain.state();
    let view = state.view();
    let generation = state.state_view_generation();
    let tip = view.native_execution_tip();
    let pool = state.evidence_preparation_budget();
    let floor = pool.reserved_bytes();
    let pointer = proof.native_frame().as_ptr();
    let hash = Hash::new(proof.native_frame());
    let observed = Cell::new(0);
    let narrow = norito::DecodeLimits::new(usize::MAX, 1, usize::MAX, usize::MAX, usize::MAX);
    let failure = norito::with_decode_limits_scope(narrow, || {
        AdmissionRead::capture_observing(
            state,
            &view,
            generation,
            3,
            std::slice::from_ref(&proof),
            |frame| {
                assert!(frame.belongs_to(pool));
                assert_ne!(frame.as_slice().as_ptr(), pointer);
                assert_eq!(frame.as_slice(), proof.native_frame());
                assert_eq!(Hash::new(frame.as_slice()), hash);
                assert!(pool.reserved_bytes() >= floor + frame.capacity());
                observed.set(observed.get() + 1);
            },
        )
    })
    .err()
    .expect("actual canonical decoder refuses caller field ceiling");
    assert_eq!(observed.get(), 1, "refusal reached charged-source decoder");
    assert!(
        matches!(
            failure,
            EvidenceAdmissionError::Preparation(EvidencePreparationError::DecodeResource(_))
        ),
        "{failure:?}"
    );
    assert!(retryable(&failure));
    assert_eq!(
        pool.reserved_bytes(),
        floor,
        "failed initial capture retires source backing"
    );
    assert_eq!(proof.native_frame().as_ptr(), pointer);
    assert_eq!(Hash::new(proof.native_frame()), hash);
    assert_eq!(state.state_view_generation(), generation);
    assert_eq!(view.native_execution_tip(), tip);
    let mut read = AdmissionRead::capture_observing(
        state,
        &view,
        generation,
        3,
        std::slice::from_ref(&proof),
        |frame| {
            assert!(frame.belongs_to(pool));
            assert_ne!(frame.as_slice().as_ptr(), pointer);
            assert_eq!(Hash::new(frame.as_slice()), hash);
            observed.set(observed.get() + 1);
        },
    )
    .unwrap();
    assert_eq!(observed.get(), 2);
    read.complete().unwrap();
    let admitted = read.finish().unwrap();
    assert_eq!(
        admitted.as_slice()[0].key(),
        super::super::evidence_key(&proof)
    );
    drop(admitted);
    drop(failure);
    assert_eq!(pool.reserved_bytes(), floor);
    assert_eq!(state.state_view_generation(), generation);
    assert_eq!(view.native_execution_tip(), tip);
}

#[test]
fn malformed_charged_evidence_cannot_gain_admission_or_mutate_original_cut() {
    let _epoch = crossbeam_epoch::pin();
    let mut chain = super::super::tests::chain();
    chain.commit(Vec::new());
    let mut proof = Evidence::from_native(&super::super::tests::conflict(&chain, 2)).unwrap();
    *proof.native.last_mut().unwrap() ^= 1;
    let state = chain.state();
    let view = state.view();
    let generation = state.state_view_generation();
    let tip = view.native_execution_tip();
    let pool = state.evidence_preparation_budget();
    let floor = pool.reserved_bytes();
    let observed = Cell::new(false);
    let error = AdmissionRead::capture_observing(
        state,
        &view,
        generation,
        3,
        std::slice::from_ref(&proof),
        |frame| {
            assert!(frame.belongs_to(pool));
            assert_eq!(frame.as_slice(), proof.native_frame());
            assert_ne!(frame.as_slice().as_ptr(), proof.native_frame().as_ptr());
            observed.set(true);
        },
    )
    .err()
    .expect("actual canonical checksum is mandatory");
    assert!(observed.get());
    assert!(matches!(error, EvidenceAdmissionError::Invalid(_)));
    assert!(!retryable(&error));
    assert_eq!(pool.reserved_bytes(), floor);
    assert_eq!(state.state_view_generation(), generation);
    assert_eq!(view.native_execution_tip(), tip);
}
