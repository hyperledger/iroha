//! Exact original carrier, due-height and replay controls for the sole penalty lifecycle.
use super::*;
use crate::sumeragi::test_chain::CertifiedTestChain;

fn pending_chain() -> (
    CertifiedTestChain,
    Hash,
    crate::state::RetainedEvidenceRecord,
) {
    let mut chain = super::tests::chain();
    chain.commit(Vec::new());
    let native = super::tests::conflict(&chain, 2);
    let key = evidence_key(&Evidence::from_native(&native).unwrap());
    assert!(observe(chain.state(), &native).unwrap());
    chain.commit(Vec::new());
    let record = chain
        .state()
        .view()
        .world()
        .consensus_evidence()
        .get(&key)
        .unwrap()
        .clone();
    assert_eq!(record.recorded_at_height, 3);
    assert_eq!(record.penalty_status, EvidencePenaltyStatus::Pending);
    (chain, key, record)
}
fn applied_chain() -> (
    CertifiedTestChain,
    Hash,
    crate::state::RetainedEvidenceRecord,
) {
    let (mut chain, key, _) = pending_chain();
    chain.commit(Vec::new());
    chain.commit(Vec::new());
    let record = chain
        .state()
        .view()
        .world()
        .consensus_evidence()
        .get(&key)
        .unwrap()
        .clone();
    assert_eq!(
        record.penalty_status,
        EvidencePenaltyStatus::Applied { height: 5 }
    );
    validate_persisted_records(chain.state()).unwrap();
    (chain, key, record)
}
fn replace_record(
    state: &State,
    original_key: Hash,
    key: Hash,
    record: crate::state::RetainedEvidenceRecord,
) {
    let mut records = state.world.consensus_evidence.block();
    records.remove(original_key);
    records.insert(key, record);
    records.commit();
}
fn assert_refusal_preserves_original_tip(
    state: &State,
    key: Hash,
    record: &crate::state::RetainedEvidenceRecord,
    reason: &str,
) {
    let tip = state.view().native_execution_tip();
    let error =
        validate_persisted_records(state).expect_err("forged snapshot is not execution authority");
    assert!(
        error.to_string().contains(reason),
        "unexpected original-source refusal: {error}"
    );
    assert_eq!(state.view().native_execution_tip(), tip);
    assert_eq!(
        state.view().world().consensus_evidence().get(&key),
        Some(record)
    );
}

#[test]
fn original_pending_and_due_applied_records_restore_against_actual_certified_carriers() {
    let (mut chain, key, pending) = pending_chain();
    validate_persisted_records(chain.state()).unwrap();
    chain.commit(Vec::new());
    assert_eq!(
        chain.state().view().world().consensus_evidence().get(&key),
        Some(&pending)
    );
    validate_persisted_records(chain.state()).unwrap();
    chain.commit(Vec::new());
    let view = chain.state().view();
    assert_eq!(
        view.world()
            .consensus_evidence()
            .get(&key)
            .unwrap()
            .penalty_status,
        EvidencePenaltyStatus::Applied { height: 5 }
    );
    let carrier = view
        .canonical_history()
        .executed_receipt(std::num::NonZeroUsize::new(5).unwrap(), |_, _| Ok(()))
        .unwrap();
    assert!(carrier.block().npos_consensus_effects().unwrap().penalty_actions.iter().any(|action| matches!(action, NposPenaltyAction::MarkConsensusEvidenceApplied(mark) if mark.evidence_key == key && mark.height == 5)));
    drop(view);
    validate_persisted_records(chain.state()).unwrap();
}

#[test]
fn wrong_height_and_overdue_pending_cannot_reopen_original_applied_evidence() {
    let (chain, key, original) = applied_chain();
    let tip = chain.state().view().native_execution_tip();
    for status in [
        EvidencePenaltyStatus::Applied { height: 0 },
        EvidencePenaltyStatus::Applied { height: 3 },
        EvidencePenaltyStatus::Applied { height: 4 },
        EvidencePenaltyStatus::Applied { height: 6 },
        EvidencePenaltyStatus::Applied { height: u64::MAX },
        EvidencePenaltyStatus::Pending,
    ] {
        let mut record = original.clone();
        record.penalty_status = status;
        replace_record(chain.state(), key, key, record.clone());
        assert_refusal_preserves_original_tip(
            chain.state(),
            key,
            &record,
            "restored penalty lifecycle is impossible",
        );
    }
    replace_record(chain.state(), key, key, original);
    assert_eq!(chain.state().view().native_execution_tip(), tip);
    validate_persisted_records(chain.state()).unwrap();
}

#[test]
fn signed_unadmitted_foreign_record_and_forged_carrier_metadata_never_restore() {
    let (chain, key, original) = applied_chain();
    // Use the original historical certificate authority. A current ready-height
    // view cannot reconstruct a past vote after its executed scheduling state moves.
    let native = NativeEvidence::ConflictingCertificates(
        chain.commit_qc(
            2,
            iroha_sumeragi::types::Hash32([0x81; 32]),
            iroha_sumeragi::types::Hash32([0x82; 32]),
            crate::sumeragi::test_chain::Signers::Quorum,
        ),
        chain.commit_qc(
            2,
            iroha_sumeragi::types::Hash32([0x83; 32]),
            iroha_sumeragi::types::Hash32([0x84; 32]),
            crate::sumeragi::test_chain::Signers::LastThree,
        ),
    );
    let verified = super::super::evidence_history::verify_from_state(
        &chain.state().view(),
        &native,
        |_, _| Ok(()),
    )
    .unwrap();
    let evidence = Evidence::from_native(&native).unwrap();
    let foreign_key = evidence_key(&evidence);
    assert_ne!(foreign_key, key);
    let mut foreign = original.canonical_projection();
    foreign.evidence = evidence;
    foreign.attribution = verified.into_attribution().get().clone();
    // Both artifact signatures and the complete current original attribution
    // are genuine. H3 admitted another proof, so no carrier admits this record.
    let foreign = crate::state::RetainedEvidenceRecord::from_fixture(
        foreign,
        &chain.state().ivm_execution_budget(),
    )
    .unwrap();
    replace_record(chain.state(), key, foreign_key, foreign.clone());
    assert_refusal_preserves_original_tip(
        chain.state(),
        foreign_key,
        &foreign,
        "restored evidence was not included by its original recorded carrier",
    );
    replace_record(chain.state(), foreign_key, key, original.clone());
    for mutate in [0, 1, 2] {
        let mut record = original.canonical_projection();
        match mutate {
            0 => record.recorded_at_view += 1,
            1 => record.recorded_at_ms += 1,
            _ => record.attribution.authority_generation[0] ^= 1,
        }
        let record = crate::state::RetainedEvidenceRecord::from_fixture(
            record,
            &chain.state().ivm_execution_budget(),
        )
        .unwrap();
        replace_record(chain.state(), key, key, record.clone());
        assert_refusal_preserves_original_tip(
            chain.state(),
            key,
            &record,
            if mutate < 2 {
                "restored evidence was not included by its original recorded carrier"
            } else {
                "restored attribution differs from original native history"
            },
        );
    }
    replace_record(chain.state(), key, key, original);
    validate_persisted_records(chain.state()).unwrap();
}

#[test]
fn original_terminal_evidence_replay_cannot_reenter_admission_or_change_records() {
    let (chain, key, original) = applied_chain();
    let tip = chain.state().view().native_execution_tip();
    let view = chain.state().view();
    let Err(error) = admission::AdmissionRead::capture(
        chain.state(),
        &view,
        chain.state().state_view_generation(),
        6,
        &[original.evidence.clone()],
    ) else {
        panic!("prior committed evidence is a replay fence after finality application");
    };
    assert!(
        matches!(
            &error,
            EvidenceAdmissionError::Invalid(reason) if reason == "evidence is already committed"
        ),
        "unexpected replay refusal: {error}"
    );
    assert_eq!(view.world().consensus_evidence().get(&key), Some(&original));
    assert_eq!(view.native_execution_tip(), tip);
}

#[test]
fn world_evidence_current_undo_and_cow_retain_original_proof_and_offender_allocations() {
    let (mut chain, key, pending) = pending_chain();
    let proof_pointer = pending.evidence.native_frame().as_ptr();
    let offenders_pointer = pending.attribution.offenders.as_ptr();
    assert!(!pending.attribution.offenders.is_empty());
    let compact_pointer = pending.attribution.offenders[0]
        .peer_id
        .public_key()
        .borrowed_parts()
        .unwrap()
        .1
        .as_ptr();
    let copied = pending.clone();
    assert_eq!(
        copied.evidence.native_frame().as_ptr(),
        proof_pointer,
        "World COW must share the original paid proof allocation"
    );
    assert_eq!(
        copied.attribution.offenders.as_ptr(),
        offenders_pointer,
        "World COW must share the original paid offender vector"
    );
    assert_eq!(
        copied.attribution.offenders[0]
            .peer_id
            .public_key()
            .borrowed_parts()
            .unwrap()
            .1
            .as_ptr(),
        compact_pointer,
        "World COW must share the original paid compact key"
    );
    chain.commit(Vec::new());
    chain.commit(Vec::new());
    let source = chain.state().world.consensus_evidence.snapshot();
    let applied = source.current().get(&key).unwrap();
    let previous = source.revert_map().get(&key).unwrap().as_ref().unwrap();
    assert_eq!(pending.penalty_status, EvidencePenaltyStatus::Pending);
    assert_eq!(previous.penalty_status, EvidencePenaltyStatus::Pending);
    assert_eq!(
        applied.penalty_status,
        EvidencePenaltyStatus::Applied { height: 5 }
    );
    for record in [previous, applied] {
        assert_eq!(record.evidence.native_frame().as_ptr(), proof_pointer);
        assert_eq!(record.attribution.offenders.as_ptr(), offenders_pointer);
        assert_eq!(
            record.attribution.offenders[0]
                .peer_id
                .public_key()
                .borrowed_parts()
                .unwrap()
                .1
                .as_ptr(),
            compact_pointer
        );
    }
    assert_eq!(copied.penalty_status, EvidencePenaltyStatus::Pending);
    drop(source);
    validate_persisted_records(chain.state()).unwrap();
}
