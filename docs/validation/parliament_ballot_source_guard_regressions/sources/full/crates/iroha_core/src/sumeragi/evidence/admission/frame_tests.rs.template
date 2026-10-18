//! Original signed certificate conflicts retain canonical frames under their finite pool.
use super::*;
use crate::sumeragi::test_chain::{CertifiedTestChain, Signers};
use iroha_sumeragi::types::Hash32;

fn signed_conflict(chain: &CertifiedTestChain) -> Evidence {
    let committed = chain.committed(2);
    let first = chain.commit_qc(2, Hash32([0x31; 32]), committed.result(), Signers::Quorum);
    let second = chain.commit_qc(
        2,
        Hash32([0x32; 32]),
        committed.result(),
        Signers::LastThree,
    );
    Evidence::from_native(&NativeEvidence::ConflictingCertificates(first, second)).unwrap()
}
#[test]
fn retained_native_evidence_frames_belong_to_original_preparation_pool() {
    let mut chain = super::super::tests::chain();
    chain.commit(Vec::new());
    let proof = signed_conflict(&chain);
    let original = proof.native_frame().to_vec();
    let state = chain.state();
    let generation = state.state_view_generation();
    let budget = state.evidence_preparation_budget();
    let epoch = crossbeam_epoch::pin();
    let baseline = budget.reserved_bytes();
    let view = state.view();
    let mut read =
        AdmissionRead::capture(state, &view, generation, 3, std::slice::from_ref(&proof))
            .expect("real quorum signatures; attachments grant no native authority");
    drop(view);
    read.complete().unwrap();
    let candidate = &read.candidates.as_slice()[0];
    assert!(
        candidate
            .verified
            .as_ref()
            .unwrap()
            .body
            .as_ref()
            .unwrap()
            .proof_belongs_to(budget)
    );
    assert_eq!(
        candidate.verified.as_ref().unwrap().native_frame().unwrap(),
        original
    );
    let admitted = read.finish().unwrap();
    assert!(admitted.belongs_to(budget));
    assert!(admitted.as_slice()[0].attribution().safety_violation);
    assert_eq!(proof.native_frame(), original);
    drop(admitted);
    assert_eq!(budget.reserved_bytes(), baseline);
    drop(epoch);
}

#[test]
fn frame_refusal_refunds_failed_capture_and_retries_original_source() {
    let mut chain = super::super::tests::chain();
    chain.commit(Vec::new());
    let proof = signed_conflict(&chain);
    let original = proof.native_frame().to_vec();
    let state = chain.state();
    let generation = state.state_view_generation();
    let budget = state.evidence_preparation_budget();
    let epoch = crossbeam_epoch::pin();
    let baseline = budget.reserved_bytes();
    let previous_limit = budget.limit_bytes();
    // Candidate and output slots fit; the canonical original frame does not.
    let before_frame =
        std::mem::size_of::<Candidate>() + std::mem::size_of::<super::super::AdmittedEvidence>();
    budget.set_limit_bytes(baseline + before_frame + original.len() - 1);
    let view = state.view();
    let failure =
        match AdmissionRead::capture(state, &view, generation, 3, std::slice::from_ref(&proof)) {
            Ok(_) => panic!("original frame must be refused"),
            Err(error) => error,
        };
    let EvidenceAdmissionError::Preparation(EvidencePreparationError::Admission(
        iroha_allocation::AllocationRefusal::Capacity {
            requested_bytes, ..
        },
    )) = &failure
    else {
        panic!("exact original-pool refusal: {failure:?}")
    };
    assert_eq!(*requested_bytes, original.len());
    assert!(retryable(&failure));
    assert_eq!(
        budget.reserved_bytes(),
        baseline,
        "failed capture retains no decoded progress"
    );
    assert_eq!(proof.native_frame(), original);
    assert_eq!(state.state_view_generation(), generation);
    budget.set_limit_bytes(previous_limit);
    let mut retry =
        AdmissionRead::capture(state, &view, generation, 3, std::slice::from_ref(&proof)).unwrap();
    drop(view);
    retry.complete().unwrap();
    assert!(
        retry.candidates.as_slice()[0]
            .verified
            .as_ref()
            .unwrap()
            .body
            .as_ref()
            .unwrap()
            .proof_belongs_to(budget)
    );
    let admitted = retry.finish().unwrap();
    assert!(admitted.as_slice()[0].attribution().safety_violation);
    drop(admitted);
    assert_eq!(budget.reserved_bytes(), baseline);
    drop(epoch);
}

#[test]
fn funded_frames_do_not_authorize_invalid_original_signatures() {
    let mut chain = super::super::tests::chain();
    chain.commit(Vec::new());
    let proof = signed_conflict(&chain);
    let mut native = proof.decode_native().unwrap();
    let NativeEvidence::ConflictingCertificates(first, _) = &mut native else {
        panic!("original signed pair")
    };
    first.agg_sig.0[0] ^= 1;
    let invalid = Evidence::from_native(&native).unwrap();
    let state = chain.state();
    let epoch = crossbeam_epoch::pin();
    let baseline = state.evidence_preparation_budget().reserved_bytes();
    let view = state.view();
    let rejected =
        AdmissionRead::capture(state, &view, state.state_view_generation(), 3, &[invalid]);
    assert!(matches!(rejected, Err(EvidenceAdmissionError::Invalid(_))));
    assert_eq!(
        state.evidence_preparation_budget().reserved_bytes(),
        baseline
    );
    drop(view);
    drop(epoch);
}
