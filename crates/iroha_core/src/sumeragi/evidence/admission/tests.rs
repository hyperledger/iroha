//! Exact retained root replay semantics and original-pool admission descriptors.
use super::*;

#[test]
fn admission_owner_preserves_root_authority_and_refunds_exact_original_backing() {
    let _epoch = crossbeam_epoch::pin();
    let mut chain = super::super::tests::chain();
    chain.commit(Vec::new());
    let proof = Evidence::from_native(&super::super::tests::conflict(&chain, 2)).unwrap();
    let state = chain.state();
    let generation = state.state_view_generation();
    let budget = state.evidence_preparation_budget();
    let baseline = budget.reserved_bytes();
    budget.set_limit_bytes(baseline);
    assert!(matches!(
        AdmissionRead::capture(
            state,
            &state.view(),
            generation,
            3,
            std::slice::from_ref(&proof)
        ),
        Err(EvidenceAdmissionError::Preparation(_))
    ));
    assert_eq!(budget.reserved_bytes(), baseline);
    budget.set_limit_bytes(1 << 30);
    let mut read = AdmissionRead::capture(
        state,
        &state.view(),
        generation,
        3,
        std::slice::from_ref(&proof),
    )
    .unwrap();
    assert!(read.matches(generation, 3, std::slice::from_ref(&proof)));
    assert!(!read.matches(generation + 2, 3, std::slice::from_ref(&proof)));
    assert!(!read.matches(generation, 4, std::slice::from_ref(&proof)));
    assert!(!read.matches(generation, 3, &[]));
    let captured = budget.reserved_bytes();
    assert!(captured > baseline);
    read.complete().unwrap();
    let admitted = read.finish().unwrap();
    assert!(admitted.belongs_to(budget));
    assert_eq!(admitted.as_slice()[0].key(), evidence_key(&proof));
    assert_eq!(
        admitted.as_slice()[0].attribution().scope,
        iroha_data_model::block::consensus::EvidenceScope::Root
    );
    assert_eq!(admitted.as_slice()[0].attribution().height, 2);
    assert_eq!(
        admitted.as_slice()[0]
            .attribution()
            .offenders
            .iter()
            .map(|offender| offender.signer)
            .collect::<Vec<_>>(),
        vec![1, 2]
    );
    assert!(
        admitted.as_slice()[0]
            .attribution()
            .offenders
            .iter()
            .all(|offender| offender.lane_stake.is_none())
    );
    drop(admitted);
    assert_eq!(budget.reserved_bytes(), baseline);
}

#[test]
fn admission_owner_retains_exact_key_and_original_signer_replay_fences() {
    let mut chain = super::super::tests::chain();
    chain.commit(Vec::new());
    let native = super::super::tests::conflict(&chain, 2);
    let proof = Evidence::from_native(&native).unwrap();
    let other = Evidence::from_native(&super::super::tests::vote_pair(&chain, 1, 4)).unwrap();
    observe(chain.state(), &native).unwrap();
    chain.commit(Vec::new());
    let state = chain.state();
    let generation = state.state_view_generation();
    assert!(
        matches!(AdmissionRead::capture(state, &state.view(), generation, 4, &[proof]), Err(EvidenceAdmissionError::Invalid(reason)) if reason == "evidence is already committed")
    );
    let mut read = AdmissionRead::capture(state, &state.view(), generation, 4, &[other]).unwrap();
    assert!(
        matches!(read.complete(), Err(EvidenceAdmissionError::Invalid(reason)) if reason.contains("original signer"))
    );
}

#[test]
fn admission_owner_cannot_capture_an_identical_foreign_state_view_or_odd_generation() {
    let mut chain = super::super::tests::chain();
    chain.commit(Vec::new());
    let mut other = super::super::tests::chain();
    other.commit(Vec::new());
    let proof = Evidence::from_native(&super::super::tests::conflict(&chain, 2)).unwrap();
    let state = chain.state();
    let generation = state.state_view_generation();
    assert!(
        matches!(AdmissionRead::capture(state, &other.state().view(), generation, 3, std::slice::from_ref(&proof)), Err(EvidenceAdmissionError::Source(error)) if error.io_kind() == std::io::ErrorKind::InvalidInput)
    );
    assert!(matches!(
        AdmissionRead::capture(state, &state.view(), generation | 1, 3, &[proof]),
        Err(EvidenceAdmissionError::Preparation(
            EvidencePreparationError::OriginalHistoryPending
        ))
    ));
}

#[test]
fn state_admission_cache_refuses_contention_without_blocking_empty_carriers() {
    let mut chain = super::super::tests::chain();
    chain.commit(Vec::new());
    let proof = Evidence::from_native(&super::super::tests::conflict(&chain, 2)).unwrap();
    let state = chain.state();
    let generation = state.state_view_generation();
    let baseline = state.evidence_preparation_budget().reserved_bytes();
    let held = state.native_evidence_admission.lock();
    assert!(matches!(
        prepare_admissions(state, generation, 3, std::slice::from_ref(&proof)),
        Err(EvidenceAdmissionError::Preparation(
            EvidencePreparationError::OriginalHistoryPending
        ))
    ));
    let empty = prepare_admissions(state, generation, 3, &[]).unwrap();
    assert!(empty.as_slice().is_empty());
    assert_eq!(
        state.evidence_preparation_budget().reserved_bytes(),
        baseline
    );
    drop(held);
    let admitted = prepare_admissions(state, generation, 3, &[proof]).unwrap();
    assert_eq!(admitted.as_slice().len(), 1);
    assert!(state.native_evidence_admission.lock().pending.is_none());
    drop(admitted);
    assert_eq!(
        state.evidence_preparation_budget().reserved_bytes(),
        baseline
    );
}

#[test]
fn replay_fence_funds_actual_native_roster_above_global_geometry() {
    let mut chain = super::super::tests::chain();
    chain.commit(Vec::new());
    let verified = crate::sumeragi::evidence_history::verify_from_state(
        &chain.state().view(),
        &super::super::tests::conflict(&chain, 2),
        |_, _| Ok(()),
    )
    .unwrap();
    let mut claim = verified.into_attribution().get().clone();
    claim.offenders = (0..33_u32)
        .map(|signer| {
            let pair = iroha_crypto::KeyPair::from_seed(
                (signer + 1).to_le_bytes().to_vec(),
                iroha_crypto::Algorithm::BlsNormal,
            );
            EvidenceOffender {
                signer,
                peer_id: iroha_model_base::peer::PeerId::new(pair.public_key().clone()),
                lane_stake: None,
            }
        })
        .collect();
    let budget = AllocationBudget::new(33 * std::mem::size_of::<OriginalSigner>());
    let mut backing = ChargedBuffer::new(33, &budget).unwrap();
    let fence = ReplayFence::new(
        Hash::new(b"geometry-only replay fence"),
        true,
        &claim,
        &mut backing,
    )
    .unwrap();
    assert_eq!(fence.count, 33);
    assert!(fence.shares(&claim, backing.as_slice()).unwrap());
    assert_eq!(
        budget.reserved_bytes(),
        33 * std::mem::size_of::<OriginalSigner>()
    );
    let mut missing = claim.clone();
    missing.offenders.clear();
    assert!(!fence.shares(&missing, backing.as_slice()).unwrap());
    drop(backing);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn retained_admission_classifies_only_typed_local_refusal_as_retryable() {
    use iroha_data_model::query::error::QueryExecutionFail;
    use std::io::ErrorKind;
    for kind in [ErrorKind::WouldBlock, ErrorKind::Interrupted] {
        assert!(retryable(&EvidenceAdmissionError::Source(
            std::io::Error::from(kind).into()
        )));
    }
    for kind in [
        ErrorKind::NotFound,
        ErrorKind::InvalidData,
        ErrorKind::PermissionDenied,
    ] {
        assert!(
            !retryable(&EvidenceAdmissionError::Source(
                std::io::Error::from(kind).into()
            )),
            "{kind:?}"
        );
    }
    assert!(retryable(&EvidenceAdmissionError::History(
        crate::execution_attempt::ExecutionAttemptError::Rejected(
            QueryExecutionFail::GasBudgetExceeded
        )
    )));
    assert!(!retryable(&EvidenceAdmissionError::History(
        crate::execution_attempt::ExecutionAttemptError::Rejected(QueryExecutionFail::Conversion(
            "bad source".into()
        ))
    )));
    assert!(retryable(
        &EvidencePreparationError::OriginalHistoryPending.into()
    ));
    assert!(!retryable(&EvidencePreparationError::Invariant.into()));
    assert!(!retryable(
        &EvidencePreparationError::Admission(iroha_allocation::AllocationRefusal::DemandOverflow)
            .into()
    ));
    assert!(retryable(
        &EvidencePreparationError::Admission(iroha_allocation::AllocationRefusal::ExceedsLimit {
            requested_bytes: 2,
            limit_bytes: 1
        })
        .into()
    ));
}

#[test]
fn admitted_offender_graph_keeps_original_execution_pool_until_last_graph_drop() {
    let mut chain = super::super::tests::chain();
    chain.commit(Vec::new());
    let state = chain.state();
    let native = super::super::tests::conflict(&chain, 2);
    let proof = Evidence::from_native(&native).unwrap();
    let execution = state.ivm_execution_budget();
    let preparation = state.evidence_preparation_budget();
    let execution_before = execution.reserved_bytes();
    let preparation_before = preparation.reserved_bytes();
    let generation = state.state_view_generation();
    let mut read = AdmissionRead::capture(
        state,
        &state.view(),
        generation,
        3,
        std::slice::from_ref(&proof),
    )
    .unwrap();
    read.complete().unwrap();
    let owner = read.candidates.as_slice()[0].verified.as_ref().unwrap();
    let graph = owner.attribution();
    assert!(owner.attribution_belongs_to(&execution));
    assert!(!owner.attribution_belongs_to(preparation));
    let original = graph.offenders.as_ptr();
    let compact = graph.offenders[0]
        .peer_id
        .public_key()
        .borrowed_parts()
        .unwrap()
        .1
        .as_ptr();
    let bytes = owner.allocation_bytes().unwrap();
    assert_eq!(execution.reserved_bytes(), execution_before + bytes);
    let admitted = read.finish().unwrap();
    let owner = &admitted.as_slice()[0];
    let graph = owner.attribution();
    assert_eq!(graph.offenders.as_ptr(), original);
    assert_eq!(
        graph.offenders[0]
            .peer_id
            .public_key()
            .borrowed_parts()
            .unwrap()
            .1
            .as_ptr(),
        compact
    );
    assert!(owner.attribution_belongs_to(&execution));
    assert_eq!(execution.reserved_bytes(), execution_before + bytes);
    drop(admitted);
    assert_eq!(execution.reserved_bytes(), execution_before);
    assert_eq!(preparation.reserved_bytes(), preparation_before);
}

#[test]
fn late_record_shell_refusal_retains_original_verified_graph_and_frame_for_retry() {
    let mut chain = super::super::tests::chain();
    chain.commit(Vec::new());
    let state = chain.state();
    let proof = Evidence::from_native(&super::super::tests::conflict(&chain, 2)).unwrap();
    let generation = state.state_view_generation();
    let execution = state.ivm_execution_budget();
    let mut read = AdmissionRead::capture(
        state,
        &state.view(),
        generation,
        3,
        std::slice::from_ref(&proof),
    )
    .unwrap();
    let candidate = &read.candidates.as_slice()[0];
    let frame_pointer = candidate.frame.as_ref().unwrap().as_slice().as_ptr();
    let graph_pointer = candidate
        .verified
        .as_ref()
        .unwrap()
        .attribution()
        .offenders
        .as_ptr();
    let compact_pointer = candidate.verified.as_ref().unwrap().attribution().offenders[0]
        .peer_id
        .public_key()
        .borrowed_parts()
        .unwrap()
        .1
        .as_ptr();
    let graph_reserved = execution.reserved_bytes();
    let blocker = execution
        .try_reserve_bytes(execution.limit_bytes() - graph_reserved)
        .unwrap();
    let exact = iroha_allocation::ChargedShared::<super::super::record::EvidenceRecordBody>::allocation_layout();
    let expected = execution.try_reserve(exact).unwrap_err();
    let error = read
        .complete()
        .expect_err("the final original-pool record shell must refuse");
    let EvidenceAdmissionError::Preparation(EvidencePreparationError::Admission(actual)) = error
    else {
        panic!("typed original shell refusal")
    };
    assert_eq!(actual, expected);
    assert!(read.matches(generation, 3, std::slice::from_ref(&proof)));
    let candidate = &read.candidates.as_slice()[0];
    assert!(candidate.verified.as_ref().unwrap().body.is_none());
    assert_eq!(
        candidate.frame.as_ref().unwrap().as_slice().as_ptr(),
        frame_pointer
    );
    assert_eq!(
        candidate
            .verified
            .as_ref()
            .unwrap()
            .attribution()
            .offenders
            .as_ptr(),
        graph_pointer
    );
    drop(blocker);
    read.complete().unwrap();
    let admitted = read.finish().unwrap();
    let owner = &admitted.as_slice()[0];
    assert_eq!(owner.native_frame().unwrap().as_ptr(), frame_pointer);
    assert_eq!(owner.attribution().offenders.as_ptr(), graph_pointer);
    assert_eq!(
        owner.attribution().offenders[0]
            .peer_id
            .public_key()
            .borrowed_parts()
            .unwrap()
            .1
            .as_ptr(),
        compact_pointer
    );
    assert!(owner.attribution_belongs_to(&execution));
    let record = owner.record(&proof, 3, 0, 3000).unwrap();
    assert!(record.proof_belongs_to(state.evidence_preparation_budget()));
    assert!(record.body_belongs_to(&execution));
    assert_eq!(
        record.native_evidence().unwrap().native_frame().as_ptr(),
        frame_pointer
    );
    drop(admitted);
    assert_eq!(record.attribution.offenders.as_ptr(), graph_pointer);
}

#[test]
fn pending_sccp_material_never_enters_native_replay_fences() {
    use crate::sumeragi::evidence::record::{parse_record, sccp_storage_claim_for_testing};
    let pool = iroha_allocation::AllocationBudget::new(1 << 20);
    let mut data = sccp_storage_claim_for_testing();
    let text = norito::json::to_json(&data).unwrap();
    let sccp = parse_record(&mut norito::json::Parser::new(&text), &pool).unwrap();
    assert!(
        matches!(require_native_replay_record(&sccp),Err(EvidenceAdmissionError::Invalid(reason)) if reason.contains("SCCP"))
    );
    // Explicitly synthetic Native fixture tests only the closed dispatch boundary.
    data.evidence = iroha_data_model::block::consensus::RecordedEvidenceV1::Native(Evidence {
        native: Vec::new(),
    });
    data.attribution.scope = iroha_data_model::block::consensus::EvidenceScope::Root;
    let native = RetainedEvidenceRecord::from_fixture(data, &pool).unwrap();
    assert!(require_native_replay_record(&native).is_ok());
    let key = Hash::prehashed(sccp.sccp_evidence_id().unwrap());
    assert!(native_replay_record(&key, &sccp).unwrap().is_none());
    assert!(native_replay_record(&Hash::new(b"wrong SCCP table key"), &sccp).is_err());
    for record in [&native, &sccp] {
        assert_eq!(
            require_native_replay_record(record).is_ok(),
            record.native_evidence().is_some()
        );
    }
    drop(native);
    drop(sccp);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn lifecycle_dispatch_skips_only_closed_matching_sccp_material() {
    use crate::sumeragi::evidence::record::sccp_storage_claim_for_testing;
    use iroha_data_model::block::consensus::{EvidenceScope, RecordedEvidenceV1};
    let original = sccp_storage_claim_for_testing();
    assert!(native_lifecycle_evidence(&original).unwrap().is_none());
    for mutation in 0..6 {
        let mut claim = original.clone();
        match mutation {
            0 => claim.attribution.scope = EvidenceScope::Root,
            1 => claim.attribution.scope = EvidenceScope::SccpGeneration { generation: 8 },
            2 => claim.attribution.height += 1,
            3 => claim.attribution.safety_violation = false,
            4 => claim.attribution.offenders.clear(),
            5 => claim.evidence = RecordedEvidenceV1::Native(Evidence { native: Vec::new() }),
            _ => unreachable!(),
        }
        assert!(
            native_lifecycle_evidence(&claim).is_err(),
            "mutation {mutation}"
        );
    }
    let mut native = original;
    native.evidence = RecordedEvidenceV1::Native(Evidence { native: Vec::new() });
    native.attribution.scope = EvidenceScope::Root;
    assert!(native_lifecycle_evidence(&native).unwrap().is_some());
}

#[test]
fn genuine_closed_sccp_record_coexists_with_native_batch_and_original_replay_fences() {
    use crate::smartcontracts::isi::sccp::forgery;
    use iroha_data_model::block::BlockHeader;
    use std::num::NonZeroU64;
    let (chain, keys) = forgery::tests::active_member_chain();
    let evidence = forgery::tests::future(&chain, &keys);
    let proof = Evidence::from_native(&super::super::tests::conflict(&chain, 2)).unwrap();
    let state = chain.state();
    let parent = state.view().native_execution_tip().unwrap();
    let header = BlockHeader::new(
        NonZeroU64::new(parent.height() + 1).unwrap(),
        Some(parent.iroha_hash()),
        None,
        parent.creation_time_ms() + 1_000,
        0,
    );
    let (key, original) = {
        let mut block = state.block(header);
        let mut stx = block.transaction_for_callback_testing();
        forgery::execute_forgery(&evidence, &mut stx).unwrap();
        let (key, record) = stx.world.consensus_evidence.iter().next().unwrap();
        (*key, record.clone())
    };
    assert!(original.native_evidence().is_none());
    assert_eq!(original.recorded_at_height, header.height().get());
    assert_eq!(original.sccp_evidence_id().map(Hash::prehashed), Some(key));
    // Install the genuinely verified retained owner as component prestate. This is
    // not a fabricated SignedBlock/output seal or a signed-entrypoint qualification.
    for status in [
        EvidencePenaltyStatus::Pending,
        EvidencePenaltyStatus::Applied { height: 4 },
    ] {
        let mut record = original.clone();
        record.penalty_status = status;
        let mut rows = state.world.consensus_evidence.block();
        rows.insert(key, record);
        rows.commit();
        let before = state.evidence_preparation_budget().reserved_bytes();
        let generation = state.state_view_generation();
        let mut read = AdmissionRead::capture(
            state,
            &state.view(),
            generation,
            3,
            std::slice::from_ref(&proof),
        )
        .unwrap();
        assert!(read.fences.as_slice().is_empty());
        assert!(read.signers.as_slice().is_empty());
        read.complete().unwrap();
        let admitted = read.finish().unwrap();
        assert_eq!(admitted.as_slice().len(), 1);
        assert_eq!(admitted.as_slice()[0].key(), evidence_key(&proof));
        assert_eq!(admitted.as_slice()[0].attribution().offenders.len(), 2);
        drop(admitted);
        assert_eq!(state.evidence_preparation_budget().reserved_bytes(), before);
        let view = state.view();
        let retained = view.world().consensus_evidence().get(&key).unwrap();
        assert!(retained.shares_body(&original));
        assert!(!committed_evidence_record_is_prunable(view.world(), retained, u64::MAX).unwrap());
        assert!(
            committed_evidence_prune_keys_from_state(state, u64::MAX)
                .unwrap()
                .as_slice()
                .is_empty()
        );
    }
    let mut read = AdmissionRead::capture(
        state,
        &state.view(),
        state.state_view_generation(),
        3,
        std::slice::from_ref(&proof),
    )
    .unwrap();
    read.complete().unwrap();
    let admitted = read.finish().unwrap();
    let native = admitted.as_slice()[0].record(&proof, 3, 0, 3_000).unwrap();
    let mut rows = state.world.consensus_evidence.block();
    rows.insert(evidence_key(&proof), native);
    rows.commit();
    drop(admitted);
    assert!(
        matches!(AdmissionRead::capture(state, &state.view(), state.state_view_generation(), 3,
        &[proof]), Err(EvidenceAdmissionError::Invalid(reason)) if reason == "evidence is already committed")
    );
    let other = Evidence::from_native(&NativeEvidence::ConflictingCertificates(
        chain.commit_qc(
            2,
            iroha_sumeragi::types::Hash32([0x41; 32]),
            iroha_sumeragi::types::Hash32([0x42; 32]),
            crate::sumeragi::test_chain::Signers::Quorum,
        ),
        chain.commit_qc(
            2,
            iroha_sumeragi::types::Hash32([0x43; 32]),
            iroha_sumeragi::types::Hash32([0x44; 32]),
            crate::sumeragi::test_chain::Signers::LastThree,
        ),
    ))
    .unwrap();
    let mut read = AdmissionRead::capture(
        state,
        &state.view(),
        state.state_view_generation(),
        3,
        &[other],
    )
    .unwrap();
    assert_eq!(
        read.fences.as_slice().len(),
        1,
        "only Native supplies a signer fence"
    );
    assert_eq!(read.signers.as_slice().len(), 2);
    assert!(
        matches!(read.complete(), Err(EvidenceAdmissionError::Invalid(reason)) if reason.contains("original signer"))
    );
}
