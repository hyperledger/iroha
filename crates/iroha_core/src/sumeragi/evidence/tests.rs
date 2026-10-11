//! Native evidence admission, original state binding and penalty publication.
use super::*;
use crate::{
    state::World,
    sumeragi::test_chain::{CertifiedTestChain, Signers, TestChainConfig},
};
use iroha_data_model::parameter::{
    Parameter,
    system::{SumeragiConsensusMode, SumeragiNposParameters},
};
use iroha_sumeragi::{
    message::{Vote, VoteKind},
    types::{Hash32, Signature},
};

pub(super) fn chain() -> CertifiedTestChain {
    let mut config = TestChainConfig::new(World::new(), 1_000);
    config.consensus_mode = SumeragiConsensusMode::Npos;
    config.genesis_parameters.push(Parameter::Custom(
        SumeragiNposParameters {
            slashing_delay_blocks: 2,
            ..SumeragiNposParameters::default()
        }
        .into_custom_parameter(),
    ));
    CertifiedTestChain::start(config).unwrap()
}
pub(super) fn conflict(chain: &CertifiedTestChain, height: u64) -> NativeEvidence {
    NativeEvidence::ConflictingCertificates(
        chain.commit_qc(
            height,
            Hash32([0x31; 32]),
            Hash32([0x32; 32]),
            Signers::Quorum,
        ),
        chain.commit_qc(
            height,
            Hash32([0x33; 32]),
            Hash32([0x34; 32]),
            Signers::LastThree,
        ),
    )
}
#[test]
fn canonical_key_and_overflow_safe_byte_accounting() {
    let chain = chain();
    let native = conflict(&chain, 2);
    let evidence = Evidence::from_native(&native).unwrap();
    let NativeEvidence::ConflictingCertificates(a, b) = native else {
        unreachable!()
    };
    let reversed = Evidence::from_native(&NativeEvidence::ConflictingCertificates(b, a)).unwrap();
    assert_eq!(evidence, reversed);
    assert_eq!(evidence_key(&evidence), evidence_key(&reversed));
    assert_eq!(
        evidence_encoded_len(&evidence),
        evidence.native_frame().len()
    );
    assert_eq!(checked_evidence_byte_sum(2, [3, 4], 9), Some(9));
    assert_eq!(checked_evidence_byte_sum(2, [3, 5], 9), None);
    assert_eq!(checked_evidence_byte_sum(usize::MAX, [1], usize::MAX), None);
}
#[test]
fn original_native_history_authenticates_every_certificate_intersection_signer() {
    let mut chain = chain();
    chain.commit(Vec::new());
    let evidence = Evidence::from_native(&conflict(&chain, 2)).unwrap();
    let view = chain.state().view();
    let generation = chain.state().state_view_generation();
    let mut read =
        admission::AdmissionRead::capture(chain.state(), &view, generation, 3, &[evidence.clone()])
            .unwrap();
    read.complete().unwrap();
    let admissions = read.finish().unwrap();
    let attribution = admissions.as_slice()[0].attribution();
    assert_eq!(attribution.height, 2);
    assert!(attribution.safety_violation);
    assert_eq!(
        attribution
            .offenders
            .iter()
            .map(|offender| offender.signer)
            .collect::<Vec<_>>(),
        [1, 2]
    );
    for offender in &attribution.offenders {
        assert_eq!(
            offender.peer_id,
            chain.validators()[offender.signer as usize].0
        );
    }
    assert!(
        admission::AdmissionRead::capture(chain.state(), &view, generation, 2, &[evidence.clone()])
            .is_err()
    );
    assert!(
        admission::AdmissionRead::capture(
            chain.state(),
            &view,
            generation,
            3,
            &[evidence.clone(), evidence]
        )
        .is_err()
    );
}
#[test]
fn observer_pool_is_charged_and_refusal_preserves_original_source() {
    let mut chain = chain();
    chain.commit(Vec::new());
    let evidence = conflict(&chain, 2);
    let state = chain.state();
    let original_tip = state.view().native_execution_tip();
    let budget = state.evidence_preparation_budget();
    let occupation = budget.try_reserve_bytes(budget.limit_bytes()).unwrap();
    assert!(observe(state, &evidence).is_err());
    assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
    assert_eq!(state.view().native_execution_tip(), original_tip);
    assert!(
        state
            .view()
            .world()
            .consensus_evidence()
            .iter()
            .next()
            .is_none()
    );
    drop(occupation);
    assert!(observe(state, &evidence).unwrap());
    let retained = budget.reserved_bytes();
    assert!(retained > 0);
    assert!(!observe(state, &evidence).unwrap());
    assert_eq!(budget.reserved_bytes(), retained);
    let selected = pending_evidence_admissions(state, 3, state.state_view_generation());
    assert_eq!(selected.len(), 1);
    assert!(
        state
            .view()
            .world()
            .consensus_evidence()
            .iter()
            .next()
            .is_none()
    );
}

#[test]
fn captured_admission_uses_the_original_parent_even_after_successor_admission() {
    let mut chain = chain();
    chain.commit(Vec::new());
    let native = conflict(&chain, 2);
    let evidence = Evidence::from_native(&native).unwrap();
    let key = evidence_key(&evidence);
    let state = std::sync::Arc::clone(chain.state());
    assert!(observe(&state, &native).unwrap());
    let generation = state.state_view_generation();
    let parent = state.view();
    assert_eq!(parent.height(), 2);
    let mut captured =
        admission::AdmissionRead::capture(&state, &parent, generation, 3, &[evidence.clone()])
            .unwrap();
    assert!(captured.matches(generation, 3, &[evidence.clone()]));
    chain.commit(Vec::new());
    assert!(
        state
            .view()
            .world()
            .consensus_evidence()
            .get(&key)
            .is_some()
    );
    assert!(parent.world().consensus_evidence().get(&key).is_none());
    drop(parent);
    captured.complete().unwrap();
    let selected = captured.finish().unwrap();
    assert_eq!(selected.as_slice().len(), 1);
    assert_eq!(
        selected.as_slice()[0].key(),
        key,
        "admission belongs to the captured parent"
    );
    assert!(
        pending_evidence_admissions(&state, 3, generation).is_empty(),
        "publication cannot propose from an obsolete original cut"
    );
}
#[test]
fn original_carrier_admits_then_finality_terminalizes_exact_parent_evidence() {
    let mut chain = chain();
    chain.commit(Vec::new());
    let evidence = conflict(&chain, 2);
    let key = evidence_key(&Evidence::from_native(&evidence).unwrap());
    observe(chain.state(), &evidence).unwrap();
    chain.commit(Vec::new());
    {
        let view = chain.state().view();
        let record = view.world().consensus_evidence().get(&key).unwrap();
        assert_eq!(record.recorded_at_height, 3);
        assert_eq!(record.penalty_status, EvidencePenaltyStatus::Pending);
        assert_eq!(record.attribution.offenders.len(), 2);
        assert!(
            admission::AdmissionRead::capture(
                chain.state(),
                &view,
                chain.state().state_view_generation(),
                4,
                &[record.evidence.clone()]
            )
            .is_err()
        );
    }
    validate_persisted_records(chain.state()).unwrap();
    chain.commit(Vec::new());
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
    drop(view);
    validate_persisted_records(chain.state()).unwrap();
}
#[test]
fn pristine_token_rejects_an_identical_foreign_state_without_any_effect() {
    let first = chain();
    let second = chain();
    let proposal = first.proposal(None, Vec::new());
    let token = prepare(
        first.state(),
        &proposal,
        first.state().state_view_generation(),
    )
    .unwrap();
    let mut overlay = second.state().block(proposal.header());
    assert!(
        token
            .apply(
                &mut overlay,
                &proposal,
                second.state(),
                second.state().state_view_generation()
            )
            .is_err()
    );
    drop(overlay);
    assert_eq!(second.state().view().height(), 1);
}
#[test]
fn altered_signature_instance_and_epoch_never_enter_local_observations() {
    let mut chain = chain();
    chain.commit(Vec::new());
    let native = conflict(&chain, 2);
    let NativeEvidence::ConflictingCertificates(first, second) = native else {
        unreachable!()
    };
    let mut changed = first.clone();
    changed.epoch.epoch += 1;
    assert!(
        observe(
            chain.state(),
            &NativeEvidence::ConflictingCertificates(changed, second.clone())
        )
        .is_err()
    );
    let mut changed = first.clone();
    changed.instance = Hash32([0xFF; 32]);
    assert!(
        observe(
            chain.state(),
            &NativeEvidence::ConflictingCertificates(changed, second.clone())
        )
        .is_err()
    );
    let mut changed = first;
    changed.agg_sig.0[0] ^= 1;
    assert!(
        observe(
            chain.state(),
            &NativeEvidence::ConflictingCertificates(changed, second)
        )
        .is_err()
    );
    assert_eq!(
        chain.state().evidence_preparation_budget().reserved_bytes(),
        0
    );
    assert!(
        chain
            .state()
            .view()
            .world()
            .consensus_evidence()
            .iter()
            .next()
            .is_none()
    );
}
#[test]
fn same_block_proof_cannot_authorize_a_penalty() {
    let mut chain = chain();
    chain.commit(Vec::new());
    let proof = Evidence::from_native(&conflict(&chain, 2)).unwrap();
    let admissions = admission::prepare_admissions(
        chain.state(),
        chain.state().state_view_generation(),
        3,
        &[proof],
    )
    .unwrap();
    let actions = [NposPenaltyAction::MarkConsensusEvidenceApplied(
        iroha_data_model::consensus::NposMarkConsensusEvidenceAppliedAction {
            evidence_key: admissions.as_slice()[0].key(),
            height: 3,
        },
    )];
    assert!(validate_admission_penalty_separation(admissions.as_slice(), &actions).is_err());
    assert!(validate_admission_penalty_separation(admissions.as_slice(), &[]).is_ok());
}

pub(super) fn vote_pair(
    chain: &CertifiedTestChain,
    signer: u32,
    view_number: u64,
) -> NativeEvidence {
    use iroha_crypto::{Algorithm, KeyPair};
    let view = chain.state().view();
    let epoch = view
        .world()
        .consensus_schedule()
        .ready(2)
        .unwrap()
        .height_config()
        .unwrap()
        .epoch
        .id;
    let key = [0xC1, 0xC2, 0xC3, 0xC4]
        .into_iter()
        .map(|seed| KeyPair::try_from_seed(vec![seed; 32], Algorithm::BlsNormal).unwrap())
        .find(|key| key.public_key() == chain.validators()[signer as usize].0.public_key())
        .unwrap();
    let vote = |byte| {
        let mut vote = Vote {
            kind: VoteKind::Prepare,
            instance: chain.instance(),
            epoch,
            height: 2,
            view: view_number,
            block_hash: Hash32([byte; 32]),
            result: Hash32([0x72; 32]),
            signer,
            sig: Signature([0; iroha_sumeragi::types::SIGNATURE_LEN]),
        };
        vote.sig = Signature(
            iroha_crypto::Signature::new(key.private_key(), &vote.preimage())
                .payload()
                .try_into()
                .unwrap(),
        );
        vote
    };
    NativeEvidence::VoteEquivocation(vote(0x71), vote(0x73))
}
#[test]
fn signer_indices_are_canonical_and_do_not_rotate_with_view() {
    let chain = chain();
    for view_number in [0, u64::MAX] {
        let evidence = vote_pair(&chain, 2, view_number);
        let verified = super::super::evidence_history::verify_from_state(
            &chain.state().view(),
            &evidence,
            |_, _| Ok(()),
        )
        .unwrap();
        assert_eq!(
            verified.offenders(),
            &[EvidenceOffender {
                signer: 2,
                peer_id: chain.validators()[2].0.clone(),
                lane_stake: None
            }]
        );
    }
}
#[test]
fn npos_mode_does_not_remap_equal_vote_evidence_signer_indices() {
    let chain = chain();
    let proof = vote_pair(&chain, 1, 47);
    let verified =
        super::super::evidence_history::verify_from_state(&chain.state().view(), &proof, |_, _| {
            Ok(())
        })
        .unwrap();
    assert_eq!(
        verified.offenders(),
        &[EvidenceOffender {
            signer: 1,
            peer_id: chain.validators()[1].0.clone(),
            lane_stake: None
        }]
    );
}
#[test]
fn original_signer_requires_matching_height_and_in_range_roster() {
    let chain = chain();
    let NativeEvidence::VoteEquivocation(first, second) = vote_pair(&chain, 1, 0) else {
        unreachable!()
    };
    let mut wrong_height = first.clone();
    wrong_height.height += 1;
    assert!(
        super::super::evidence_history::verify_from_state(
            &chain.state().view(),
            &NativeEvidence::VoteEquivocation(wrong_height, second.clone()),
            |_, _| Ok(())
        )
        .is_err()
    );
    let mut missing_signer = first;
    missing_signer.signer = 4;
    assert!(
        super::super::evidence_history::verify_from_state(
            &chain.state().view(),
            &NativeEvidence::VoteEquivocation(missing_signer, second),
            |_, _| Ok(())
        )
        .is_err()
    );
}

#[test]
fn lane_terminal_replay_fence_uses_immutable_retirement_deadline_and_original_incarnation() {
    use iroha_data_model::{
        block::consensus::{EvidenceScope, LaneEvidenceScope},
        sumeragi_lanes::{SumeragiLaneCustody, SumeragiLaneCustodySigners, SumeragiLaneFrontier},
    };
    use iroha_model_base::topology::LaneId;
    // Predicate-only records: raw proof bytes and claimed attribution grant no admission.
    let source = World::new();
    let mut world = source.block();
    world.parameters.get_mut().set_parameter(Parameter::Custom(
        SumeragiNposParameters {
            evidence_horizon_blocks: 7,
            slashing_delay_blocks: 3,
            ..SumeragiNposParameters::default()
        }
        .into_custom_parameter(),
    ));
    let original = SumeragiLaneCustody {
        lane: LaneId::new(7),
        incarnation: [0x31; 32],
        instance: [0x32; 32],
        created_at: 10,
        signer_count: 4,
        signers: SumeragiLaneCustodySigners::default(),
        merged: SumeragiLaneFrontier::default(),
        evidence_horizon: 7,
        slashing_delay: 3,
        retired_at: None,
    };
    world
        .sumeragi_lanes
        .get_mut()
        .custody
        .push(original.clone());
    let scope = LaneEvidenceScope {
        lane: original.lane,
        incarnation: original.incarnation,
        created_at: original.created_at,
        admission_parent_height: 19,
        admission_parent_hash: HashOf::from_untyped_unchecked(Hash::new(b"parent")),
        admission_parent_core_hash: [0x33; 32],
        admission_parent_result: [0x34; 32],
    };
    let mut record = EvidenceRecord {
        evidence: Evidence { native: Vec::new() },
        attribution: EvidenceAttribution {
            scope: EvidenceScope::Lane(scope),
            instance: original.instance,
            height: u64::MAX,
            epoch: 0,
            context_id: [1; 32],
            authority_generation: [1; 32],
            offenders: Vec::new(),
            safety_violation: true,
        },
        recorded_at_height: 20,
        recorded_at_view: 0,
        recorded_at_ms: 0,
        penalty_status: EvidencePenaltyStatus::Applied { height: 23 },
    };
    assert!(
        !committed_evidence_record_is_prunable(&world, &record, u64::MAX).unwrap(),
        "live lanes retain replay fences"
    );
    world.sumeragi_lanes.get_mut().custody[0].retired_at = Some(20);
    for native in [1, u64::MAX] {
        record.attribution.height = native;
        assert!(
            !committed_evidence_record_is_prunable(&world, &record, 27).unwrap(),
            "inclusive deadline"
        );
        assert!(committed_evidence_record_is_prunable(&world, &record, 28).unwrap());
    }
    record.penalty_status = EvidencePenaltyStatus::Pending;
    assert!(!committed_evidence_record_is_prunable(&world, &record, 28).unwrap());
    record.penalty_status = EvidencePenaltyStatus::Applied { height: 23 };
    let retained = world.sumeragi_lanes.get_mut().custody.pop().unwrap();
    assert!(
        !committed_evidence_record_is_prunable(&world, &record, 28).unwrap(),
        "missing original row proves no closure"
    );
    for replacement in [
        SumeragiLaneCustody {
            incarnation: [0x41; 32],
            ..retained.clone()
        },
        SumeragiLaneCustody {
            instance: [0x42; 32],
            ..retained.clone()
        },
        SumeragiLaneCustody {
            created_at: 11,
            ..retained.clone()
        },
        SumeragiLaneCustody {
            evidence_horizon: 8,
            ..retained.clone()
        },
        SumeragiLaneCustody {
            slashing_delay: 4,
            ..retained.clone()
        },
    ] {
        world.sumeragi_lanes.get_mut().custody.push(replacement);
        assert!(!committed_evidence_record_is_prunable(&world, &record, u64::MAX).unwrap());
        world.sumeragi_lanes.get_mut().custody.clear();
    }
    world.sumeragi_lanes.get_mut().custody.push(retained);
    record.recorded_at_height = 21;
    assert!(
        !committed_evidence_record_is_prunable(&world, &record, 28).unwrap(),
        "original carrier-parent binding"
    );
}

#[test]
fn retained_lane_read_refusal_is_local_preparation_and_cannot_blame_signed_input() {
    let refusal = classify(EvidenceAdmissionError::Source(
        std::io::Error::from(std::io::ErrorKind::WouldBlock).into(),
    ));
    assert!(matches!(
        refusal,
        crate::block::BlockValidationError::EvidencePreparation(
            EvidencePreparationError::OriginalHistoryPending
        )
    ));
    let missing = classify(EvidenceAdmissionError::Source(
        std::io::Error::from(std::io::ErrorKind::NotFound).into(),
    ));
    assert!(matches!(
        missing,
        crate::block::BlockValidationError::LocalStorageRecoveryRequired { .. }
    ));
}

#[test]
fn original_lane_history_refusal_reaches_evidence_without_recovery_or_rejection() {
    use crate::{
        execution_attempt::ExecutionAttemptError as Attempt,
        state::StateReadOnly,
        sumeragi::runtime_availability::history::{HistoryCapture, HistoryScan},
    };
    use std::task::Context;
    let (chain, record, _epoch) =
        crate::sumeragi::runtime_availability::tests::npos_fixed_lane_chain_at(4);
    let state = chain.state();
    let budget = state.ivm_execution_budget();
    let baseline = budget.reserved_bytes();
    let mut registration = crate::unit_test_support::release_registration(&budget);
    let ceiling = budget.limit_bytes();
    let generation = state.state_view_generation();
    let view = state.view();
    let tip = view.native_execution_tip().unwrap();
    let capture = HistoryCapture::from_view(state, &view, generation)
        .unwrap()
        .unwrap();
    let scope = iroha_data_model::block::consensus::LaneEvidenceScope {
        lane: record.lane,
        incarnation: record.incarnation,
        created_at: record.created_at,
        admission_parent_height: tip.height(),
        admission_parent_hash: tip.iroha_hash(),
        admission_parent_core_hash: tip.core_hash().0,
        admission_parent_result: tip.result().0,
    };
    drop(view);
    let mut history = HistoryScan::open_for_evidence(capture, scope).unwrap();
    let occupied = budget
        .try_reserve_bytes(ceiling - budget.reserved_bytes())
        .unwrap();
    let error = history.complete().unwrap_err();
    let Attempt::Deferred(original) = &error else {
        panic!("original history was erased: {error:?}")
    };
    let original = original.clone();
    let Some(iroha_allocation::AllocationRefusal::Capacity { release, .. }) =
        original.allocation_refusal()
    else {
        panic!("actual original archive capacity")
    };
    let wait = release.clone();
    let mut context = Context::from_waker(std::task::Waker::noop());
    assert!(registration.poll_wait(&wait, &mut context).is_pending());
    assert!(
        matches!(classify(EvidenceAdmissionError::Source(error)), crate::block::BlockValidationError::ExecutionDeferred(retained) if retained == original)
    );
    drop(occupied);
    assert!(registration.poll_wait(&wait, &mut context).is_ready());
    history.complete().unwrap();
    let context = history
        .finish_evidence()
        .unwrap_or_else(|(_, error)| panic!("{error}"));
    assert_eq!(context.scope, scope);
    assert!(context.budget.same_pool(&budget));
    assert_eq!(budget.limit_bytes(), ceiling);
    drop(context);
    drop(registration);
    assert_eq!(budget.reserved_bytes(), baseline);
}

#[test]
fn local_lane_observations_use_inclusive_retirement_and_never_a_native_height_clock() {
    use iroha_data_model::sumeragi_lanes::{
        SumeragiLaneCustody, SumeragiLaneCustodySigners, SumeragiLaneFrontier,
    };
    use iroha_model_base::topology::LaneId;
    // Local queue predicates only: these deliberately raw frames grant no proposal authority.
    let source = World::new();
    let mut world = source.block();
    world.parameters.get_mut().set_parameter(Parameter::Custom(
        SumeragiNposParameters {
            evidence_horizon_blocks: 7,
            slashing_delay_blocks: 3,
            ..SumeragiNposParameters::default()
        }
        .into_custom_parameter(),
    ));
    let row = SumeragiLaneCustody {
        lane: LaneId::new(7),
        incarnation: [31; 32],
        instance: [32; 32],
        created_at: 10,
        signer_count: 4,
        signers: SumeragiLaneCustodySigners::default(),
        merged: SumeragiLaneFrontier::default(),
        evidence_horizon: 7,
        slashing_delay: 3,
        retired_at: None,
    };
    let lane = LocalLane {
        lane: row.lane,
        incarnation: row.incarnation,
        instance: row.instance,
        created_at: row.created_at,
    };
    world.sumeragi_lanes.get_mut().custody.push(row);
    let budget = AllocationBudget::new(1 << 20);
    let mut pool = NativeEvidencePool::default();
    for (subject, byte) in [(1, 1), (u64::MAX, 2)] {
        assert!(
            pool.retain(
                &Evidence { native: vec![byte] },
                subject,
                Some(lane),
                &budget
            )
            .unwrap()
        );
    }
    let retained = budget.reserved_bytes();
    pool.prune(&world, u64::MAX).unwrap();
    assert_eq!(pool.entries.as_ref().unwrap().as_slice().len(), 2);
    assert_eq!(
        budget.reserved_bytes(),
        retained,
        "live native reports retain original frames"
    );
    world.sumeragi_lanes.get_mut().custody[0].retired_at = Some(20);
    pool.prune(&world, 27).unwrap();
    assert_eq!(
        pool.entries.as_ref().unwrap().as_slice().len(),
        2,
        "deadline is inclusive"
    );
    pool.prune(&world, 28).unwrap();
    assert!(pool.entries.as_ref().unwrap().as_slice().is_empty());
    assert_eq!(pool.bytes, 0);
    assert_eq!(
        budget.reserved_bytes(),
        retained - 2,
        "frame bytes refund exactly; descriptor backing remains owned"
    );
    world.sumeragi_lanes.get_mut().custody[0].incarnation = [99; 32];
    assert!(
        !lane.admits_at(
            &world,
            world.sumeragi_npos_parameters().unwrap().as_ref(),
            27
        ),
        "recreated routing lane cannot reopen the original incarnation"
    );
    world.sumeragi_lanes.get_mut().custody.clear();
    assert!(
        !lane.admits_at(
            &world,
            world.sumeragi_npos_parameters().unwrap().as_ref(),
            27
        ),
        "a reclaimed original row has no admission authority"
    );
    drop(pool);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn typed_original_history_budget_refusal_defers_without_storage_recovery() {
    use crate::block::BlockValidationError;
    use iroha_data_model::query::error::{CanonicalHistoryError, QueryExecutionFail};
    use std::io::ErrorKind;
    let expected_hash = HashOf::from_untyped_unchecked(Hash::new(b"original hash"));
    for error in [
        EvidenceAdmissionError::History(crate::execution_attempt::ExecutionAttemptError::Rejected(
            QueryExecutionFail::GasBudgetExceeded,
        )),
        EvidenceAdmissionError::History(crate::execution_attempt::ExecutionAttemptError::Rejected(
            QueryExecutionFail::CapacityLimit,
        )),
        EvidenceAdmissionError::History(crate::execution_attempt::ExecutionAttemptError::Rejected(
            QueryExecutionFail::CanonicalHistory(CanonicalHistoryError::BodyUnavailable {
                height: 2,
                expected_hash,
            }),
        )),
        EvidenceAdmissionError::Source(std::io::Error::from(ErrorKind::WouldBlock).into()),
        EvidenceAdmissionError::Source(std::io::Error::from(ErrorKind::Interrupted).into()),
    ] {
        assert!(matches!(
            classify(error),
            BlockValidationError::EvidencePreparation(
                EvidencePreparationError::OriginalHistoryPending
            )
        ));
    }
    for error in [
        EvidenceAdmissionError::History(crate::execution_attempt::ExecutionAttemptError::Rejected(
            QueryExecutionFail::Conversion("invalid certificate".into()),
        )),
        EvidenceAdmissionError::History(crate::execution_attempt::ExecutionAttemptError::Rejected(
            QueryExecutionFail::CanonicalHistory(CanonicalHistoryError::BlockHeightMismatch {
                height: 2,
                actual_height: 3,
            }),
        )),
        EvidenceAdmissionError::Source(std::io::Error::from(ErrorKind::NotFound).into()),
        EvidenceAdmissionError::Source(std::io::Error::from(ErrorKind::InvalidData).into()),
    ] {
        assert!(matches!(
            classify(error),
            BlockValidationError::LocalStorageRecoveryRequired { .. }
        ));
    }
}

#[test]
fn original_npos_policy_refusal_cannot_prune_retained_evidence() {
    use crate::execution_attempt::ExecutionAttemptError;
    let mut chain = chain();
    chain.commit(Vec::new());
    let proof = conflict(&chain, 2);
    let state = chain.state();
    assert!(observe(state, &proof).unwrap());
    let view = state.view();
    let horizon = view
        .world()
        .sumeragi_npos_parameters()
        .unwrap()
        .unwrap()
        .evidence_horizon_blocks();
    let height = 2 + horizon + 1;
    let mut pending = state.native_pending_evidence.lock();
    let original = pending.entries.as_ref().unwrap().as_slice()[0]
        .frame
        .as_slice()
        .to_vec();
    let pointer = pending.entries.as_ref().unwrap().as_slice()[0]
        .frame
        .as_slice()
        .as_ptr();
    let bytes = pending.bytes;
    let reserved = state.evidence_preparation_budget().reserved_bytes();
    let error = norito::with_decode_limits_scope(
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64),
        || pending.prune(view.world(), height),
    )
    .unwrap_err();
    assert!(
        matches!(
            error,
            EvidenceAdmissionError::Policy(ExecutionAttemptError::Deferred(_))
        ),
        "{error:?}"
    );
    let retained = pending.entries.as_ref().unwrap().as_slice();
    assert_eq!(retained.len(), 1);
    assert_eq!(retained[0].frame.as_slice().as_ptr(), pointer);
    assert_eq!(retained[0].frame.as_slice(), original);
    assert_eq!(pending.bytes, bytes);
    assert_eq!(
        state.evidence_preparation_budget().reserved_bytes(),
        reserved
    );
    pending.prune(view.world(), height).unwrap();
    assert!(pending.entries.as_ref().unwrap().as_slice().is_empty());
    assert_eq!(pending.bytes, 0);
    assert!(state.evidence_preparation_budget().reserved_bytes() < reserved);
}

#[test]
fn original_signed_evidence_root_scope_refusal_stays_local_and_retries_same_state() {
    use crate::execution_attempt::ExecutionAttemptError as Attempt;
    use crate::sumeragi::{evidence_history, lanes::routing};
    use ivm::error::ExecutionDeferral;

    // Genesis execution and this genuinely signed QC pair precede any caller limit.
    let chain = chain();
    let state = chain.state();
    let native = conflict(&chain, 2);
    let original = Evidence::from_native(&native).unwrap();
    let view = state.view();
    let generation = state.state_view_generation();
    let tip = view.native_execution_tip().unwrap();
    let genesis_hash = chain.genesis().hash();
    let execution_pool = state.ivm_execution_budget();
    let preparation_pool = state.evidence_preparation_budget();
    let execution_reserved = execution_pool.reserved_bytes();
    let preparation_reserved = preparation_pool.reserved_bytes();
    let root = routing::read_routing_root_scope(view.world())
        .unwrap()
        .unwrap();
    let expected = evidence_history::verify_from_state(&view, &native, |_, _| Ok(())).unwrap();
    let original_tip = expected.tip();
    let original_instance = expected.instance();
    let original_epoch = expected.epoch();
    let original_generation = expected.authority_generation();
    let original_attribution = expected.into_attribution();
    let expected_reserved = execution_pool.reserved_bytes();
    assert!(expected_reserved > execution_reserved);
    let unlimited =
        || norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, 64);
    let refusal = || norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64);

    // The canonical reader itself proves that the metadata is valid but locally refused.
    // JSON cumulative limits have no AllocationBudget release owner; invent none.
    let original_local = norito::with_decode_limits_scope(refusal(), || {
        routing::read_routing_root_scope(view.world()).unwrap_err()
    });
    assert_eq!(
        original_local.reason(),
        ExecutionDeferral::ActiveMemoryCapacity
    );
    assert!(original_local.allocation_refusal().is_none());

    for nested in [false, true] {
        let read = || {
            norito::with_decode_limits_scope(refusal(), || {
                evidence_history::verify_from_state(&view, &native, |_, _| {
                    panic!("a refused immutable root must not acquire historical authority")
                })
            })
        };
        let error = if nested {
            norito::with_decode_limits_scope(unlimited(), read)
        } else {
            read()
        }
        .unwrap_err();
        let evidence_history::NativeEvidenceError::History(Attempt::Deferred(local)) = &error
        else {
            panic!("original signed root decode refusal was erased: {error:?}")
        };
        assert_eq!(local, &original_local);
        let admission = EvidenceAdmissionError::from(error);
        assert!(admission::retryable(&admission));
        let classified = classify(admission);
        assert!(
            matches!(classified, crate::block::BlockValidationError::ExecutionDeferred(local)
                if local == original_local),
            "root refusal must not become signed-input rejection or storage recovery"
        );
        assert_eq!(execution_pool.reserved_bytes(), expected_reserved);
        assert_eq!(preparation_pool.reserved_bytes(), preparation_reserved);
        assert_eq!(state.state_view_generation(), generation);
        assert_eq!(view.native_execution_tip(), Some(tip));
        assert_eq!(chain.genesis().hash(), genesis_hash);
        assert_eq!(
            routing::read_routing_root_scope(view.world()).unwrap(),
            Some(root)
        );
        assert_eq!(Evidence::from_native(&native).unwrap(), original);
    }

    // This is the same retained State and QC pair, without clearing or replacing any source.
    let retried = evidence_history::verify_from_state(&view, &native, |_, _| Ok(())).unwrap();
    assert_eq!(retried.tip(), original_tip);
    assert_eq!(retried.instance(), original_instance);
    assert_eq!(retried.epoch(), original_epoch);
    assert_eq!(retried.authority_generation(), original_generation);
    assert!(retried.matches_attribution(&original_attribution));
    assert!(execution_pool.reserved_bytes() > expected_reserved);
    drop(retried);
    assert_eq!(execution_pool.reserved_bytes(), expected_reserved);
    drop(original_attribution);
    assert_eq!(execution_pool.reserved_bytes(), execution_reserved);
    assert_eq!(preparation_pool.reserved_bytes(), preparation_reserved);
}

#[test]
fn original_root_observation_refusal_keeps_pending_bytes_and_same_state_retry() {
    use crate::execution_attempt::ExecutionAttemptError as Attempt;
    use crate::sumeragi::lanes::routing;
    use ivm::error::ExecutionDeferral;

    let chain = chain();
    let state = chain.state();
    let native = conflict(&chain, 2);
    let original = Evidence::from_native(&native).unwrap();
    let view = state.view();
    let generation = state.state_view_generation();
    let tip = view.native_execution_tip();
    let budget = state.evidence_preparation_budget();
    let baseline = budget.reserved_bytes();
    let ceiling = 1024 * 1024;
    let limits =
        |allocation| norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, allocation, 64);
    let policy_bytes = norito::with_decode_limits_scope(limits(ceiling), || {
        assert!(horizon(view.world()).unwrap().is_some());
        let norito::Error::TotalAllocationExceeded { attempted, limit } =
            norito::core::reserve_decode_allocation(ceiling + 1).unwrap_err()
        else {
            panic!("non-charging original policy allocation probe")
        };
        assert_eq!(limit, u64::try_from(ceiling).unwrap());
        usize::try_from(attempted).unwrap() - ceiling - 1
    });
    assert!(policy_bytes > 0);
    let expected = norito::with_decode_limits_scope(limits(policy_bytes), || {
        assert!(horizon(view.world()).unwrap().is_some());
        routing::read_routing_root_scope(view.world()).unwrap_err()
    });
    assert_eq!(expected.reason(), ExecutionDeferral::ActiveMemoryCapacity);
    assert!(expected.allocation_refusal().is_none());
    let error = norito::with_decode_limits_scope(limits(policy_bytes), || observe(state, &native))
        .unwrap_err();
    assert!(
        matches!(&error, EvidenceAdmissionError::History(Attempt::Deferred(local)) if *local == expected),
        "real root observation lost original decode refusal: {error:?}"
    );
    assert!(admission::retryable(&error));
    assert_eq!(budget.reserved_bytes(), baseline);
    {
        let pending = state.native_pending_evidence.lock();
        assert!(pending.entries.is_none());
        assert_eq!(pending.bytes, 0);
    }
    assert_eq!(state.state_view_generation(), generation);
    assert_eq!(view.native_execution_tip(), tip);
    assert_eq!(Evidence::from_native(&native).unwrap(), original);
    drop(view);

    assert!(observe(state, &native).unwrap());
    let retained = budget.reserved_bytes();
    assert!(retained > baseline);
    let original_frame = {
        let pending = state.native_pending_evidence.lock();
        let entries = pending.entries.as_ref().unwrap().as_slice();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].frame.as_slice(), original.native_frame());
        assert_eq!(entries[0].key, evidence_key(&original));
        assert_eq!(entries[0].subject_height, 2);
        assert!(entries[0].lane.is_none());
        assert_eq!(pending.bytes, original.native_frame().len());
        entries[0].frame.as_slice().as_ptr()
    };
    assert!(!observe(state, &native).unwrap());
    let pending = state.native_pending_evidence.lock();
    let entries = pending.entries.as_ref().unwrap().as_slice();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].frame.as_slice().as_ptr(), original_frame);
    assert_eq!(entries[0].frame.as_slice(), original.native_frame());
    assert_eq!(budget.reserved_bytes(), retained);
    assert_eq!(state.state_view_generation(), generation);
    assert_eq!(state.view().native_execution_tip(), tip);
}

#[test]
fn global_verified_offender_graph_retains_original_pool_through_closed_move() {
    let mut chain = chain();
    chain.commit(Vec::new());
    let native = conflict(&chain, 2);
    let state = chain.state();
    let view = state.view();
    let generation = state.state_view_generation();
    let tip = view.native_execution_tip().unwrap();
    let budget = state.ivm_execution_budget();
    let baseline = budget.reserved_bytes();
    let preparation = state.evidence_preparation_budget();
    let preparation_baseline = preparation.reserved_bytes();
    let verified =
        crate::sumeragi::evidence_history::verify_from_state(&view, &native, |_, _| Ok(()))
            .unwrap();
    assert_eq!(verified.tip(), tip);
    let offenders = verified.offenders();
    assert_eq!(
        offenders.iter().map(|row| row.signer).collect::<Vec<_>>(),
        [1, 2]
    );
    for offender in offenders {
        assert_eq!(
            offender.peer_id,
            chain.validators()[offender.signer as usize].0
        );
        assert!(offender.lane_stake.is_none());
    }
    let original_vector = offenders.as_ptr();
    let original_key = offenders[0]
        .peer_id
        .public_key()
        .borrowed_parts()
        .unwrap()
        .1
        .as_ptr();
    let held = budget.reserved_bytes();
    assert!(held > baseline);
    let mut attribution = None;
    assert_eq!(
        crate::test_allocations::allocations_during(|| {
            attribution = Some(verified.into_attribution());
        }),
        0
    );
    let attribution = attribution.unwrap();
    assert_eq!(attribution.offenders.as_ptr(), original_vector);
    assert_eq!(
        attribution.offenders[0]
            .peer_id
            .public_key()
            .borrowed_parts()
            .unwrap()
            .1
            .as_ptr(),
        original_key
    );
    assert!(attribution.belongs_to(&budget));
    assert!(!attribution.belongs_to(preparation));
    assert_eq!(attribution.allocation_bytes().unwrap(), held - baseline);
    assert_eq!(budget.reserved_bytes(), held);
    assert_eq!(preparation.reserved_bytes(), preparation_baseline);
    assert_eq!(state.state_view_generation(), generation);
    assert_eq!(view.native_execution_tip(), Some(tip));
    assert!(attribution.safety_violation);
    drop(attribution);
    assert_eq!(budget.reserved_bytes(), baseline);
    assert_eq!(preparation.reserved_bytes(), preparation_baseline);
}
