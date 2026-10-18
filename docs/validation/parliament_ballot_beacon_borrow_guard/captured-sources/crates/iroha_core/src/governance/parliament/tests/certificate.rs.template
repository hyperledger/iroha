#[test]
fn policy_margin_is_strict_and_atomic_confirmation_roster_is_fresh() {
    let mut narrow = opened_policy_ballot(100, 100);
    assert_eq!(
        finalize_policy(&mut narrow, 51, 49, 0),
        ParliamentAggregateOutcomeV1::Approved
    );
    assert_eq!(
        narrow.state.attempt.stage,
        GovernanceStageV1::ConfirmationJury
    );
    assert_eq!(
        narrow.state.required_bodies.last(),
        Some(&RequiredParliamentBodyV1 {
            body: ParliamentBody::ConfirmationJury,
            decision_mode: ParliamentDecisionModeV1::HiddenBindingBallot,
        })
    );
    let id = narrow.state.attempt.id;
    let confirmation_request_height = narrow
        .state
        .body(&narrow.body_id)
        .and_then(ParliamentBodyStateV1::result_height)
        .expect("Policy result height");
    // The slot depends only on frozen attempt fields and the attempt's generation history.
    let before_confirmation = narrow.state.clone();
    let confirmation_pulse_height = generation_slot(
        &before_confirmation,
        confirmation_request_height,
        beacon_session(104),
    );
    assert_eq!(
        (confirmation_pulse_height + 1) % narrow.state.sortition_pulse_epoch_length_blocks(),
        0,
        "the Confirmation Jury slot is a consensus-native pulse height"
    );
    assert!(
        confirmation_pulse_height
            >= confirmation_request_height + narrow.state.sortition_pulse_delay_blocks()
    );
    let policy_members: Vec<_> = narrow
        .state
        .bodies
        .values()
        .find(|body| body.instance.body == ParliamentBody::PolicyJury)
        .expect("completed policy body")
        .assignments
        .iter()
        .take(3)
        .map(|assignment| assignment.member.clone())
        .collect();
    let mut overlapping_candidates = policy_members.clone();
    overlapping_candidates.sort_unstable();
    let overlapping_election_id =
        BodyElectionAttemptId::derive_v1(id, ParliamentBody::ConfirmationJury, 0);
    let overlapping_request = SortitionRequestV1::try_new_canonical(
        id,
        overlapping_election_id,
        ParliamentBody::ConfirmationJury,
        parliament_candidate_root_v1(
            id,
            ParliamentBody::ConfirmationJury,
            &overlapping_candidates,
        ),
        u32::try_from(overlapping_candidates.len()).expect("fixture candidate count"),
        3,
        confirmation_request_height,
        confirmation_pulse_height,
        beacon_session(104),
        None,
    )
    .expect("canonical overlapping confirmation request");
    assert_eq!(
        narrow
            .state
            .register_sortition_request(id, 0, overlapping_request, overlapping_candidates,),
        Err(ParliamentReducerErrorV1::ConfirmationJuryNotFresh)
    );
    let (request, candidate_snapshot) = sortition_request(
        id,
        0,
        ParliamentBody::ConfirmationJury,
        150,
        3,
        3,
        confirmation_request_height,
        confirmation_pulse_height,
        beacon_session(104),
        None,
    );
    let confirmation_request_id = request.id;
    let confirmation_election_id = request.body_election_attempt_id;
    let all_policy_members = narrow
        .state
        .sealed_body_for_role(ParliamentBody::PolicyJury)
        .expect("completed policy body")
        .assignments
        .iter()
        .map(|assignment| assignment.member.clone())
        .collect::<BTreeSet<_>>();
    assert!(
        candidate_snapshot
            .iter()
            .all(|candidate| !all_policy_members.contains(candidate)),
        "fresh confirmation fixture candidates must exclude every Policy Jury member"
    );
    let mut delayed_transition = narrow.state.clone();
    let mut delayed_request = request;
    delayed_request.request_height = confirmation_request_height + 1;
    delayed_request.pulse_height = generation_slot(
        &delayed_transition,
        delayed_request.request_height,
        beacon_session(104),
    );
    delayed_request.id = delayed_request.canonical_id();
    assert_eq!(
        delayed_transition.register_sortition_request(
            id,
            0,
            delayed_request,
            candidate_snapshot.clone(),
        ),
        Err(ParliamentReducerErrorV1::ConfirmationJuryNotFresh),
        "the first Confirmation snapshot must be registered atomically at the Policy result height"
    );
    narrow
        .state
        .register_sortition_request(id, 0, request, candidate_snapshot)
        .expect("atomically register fresh confirmation draw");
    assert_eq!(
        narrow
            .state
            .election(&confirmation_election_id)
            .expect("registered Confirmation election")
            .attempt()
            .request
            .request_height,
        confirmation_request_height,
        "the Confirmation electorate is frozen at the Policy result height"
    );
    narrow
        .state
        .validate()
        .expect("atomic Confirmation request must restore canonically");
    let mut missing = narrow.state.clone();
    let removed = missing
        .elections
        .remove(&confirmation_election_id)
        .expect("registered Confirmation election");
    missing
        .active_elections
        .remove(&ParliamentBody::ConfirmationJury);
    let snapshot_index = usize::try_from(removed.candidate_snapshot_index)
        .expect("fixture snapshot index fits usize");
    assert_eq!(
        snapshot_index + 1,
        missing.candidate_snapshots.len(),
        "the atomic Confirmation fixture owns the final candidate snapshot"
    );
    missing
        .candidate_snapshots
        .pop()
        .expect("registered Confirmation candidate snapshot");
    assert_eq!(
        missing.validate(),
        Err(ParliamentReducerErrorV1::ConfirmationJuryNotFresh),
        "restore must reject a narrow Policy approval without its atomic Confirmation request"
    );
    let mut backdated = narrow.state.clone();
    let request = &mut backdated
        .elections
        .get_mut(&confirmation_election_id)
        .expect("registered Confirmation election")
        .attempt
        .request;
    request.request_height = confirmation_request_height - 1;
    request.pulse_height = generation_slot(
        &before_confirmation,
        request.request_height,
        beacon_session(104),
    );
    request.id = request.canonical_id();
    assert_eq!(
        backdated.validate(),
        Err(ParliamentReducerErrorV1::ConfirmationJuryNotFresh),
        "restore must reject a Confirmation snapshot backdated before the Policy result"
    );
    let mut delayed = narrow.state.clone();
    let request = &mut delayed
        .elections
        .get_mut(&confirmation_election_id)
        .expect("registered Confirmation election")
        .attempt
        .request;
    request.request_height = confirmation_request_height + 1;
    request.pulse_height = generation_slot(
        &before_confirmation,
        request.request_height,
        beacon_session(104),
    );
    request.id = request.canonical_id();
    assert_eq!(
        delayed.validate(),
        Err(ParliamentReducerErrorV1::ConfirmationJuryNotFresh),
        "restore must reject a sequence-zero Confirmation snapshot delayed past the Policy result"
    );
    consume_sortition(
        &mut narrow.state,
        id,
        vec![confirmation_request_id],
        beacon_session(104),
        confirmation_pulse_height,
        pulse_id(105),
    )
    .expect("consume confirmation pulse");
    narrow
        .state
        .begin_invitation_acceptance(id, confirmation_election_id, confirmation_pulse_height, 1)
        .expect("confirmation invitations");
    let confirmation_members: Vec<_> = narrow
        .state
        .election(&confirmation_election_id)
        .expect("drawn confirmation election")
        .primary_assignments()
        .iter()
        .map(|assignment| assignment.member.clone())
        .collect();
    for member in confirmation_members {
        narrow
            .state
            .record_invitation_response(
                id,
                confirmation_election_id,
                &member,
                true,
                confirmation_pulse_height,
            )
            .expect("accept confirmation invitation");
    }
    narrow
        .state
        .seal_body_roster(id, confirmation_election_id, confirmation_pulse_height + 1)
        .expect("disjoint confirmation roster");

    let mut exact_five = opened_policy_ballot(40, 40);
    assert_eq!(
        finalize_policy(&mut exact_five, 21, 19, 0),
        ParliamentAggregateOutcomeV1::Approved
    );
    assert_eq!(
        exact_five.state.attempt.stage,
        GovernanceStageV1::Certification
    );
    assert!(
        exact_five
            .state
            .required_bodies
            .iter()
            .all(|required| required.body != ParliamentBody::ConfirmationJury)
    );
}

#[test]
fn certificate_and_terminal_transition_table_are_fail_closed() {
    let mut fixture = opened_policy_ballot(3, 3);
    assert_eq!(
        finalize_policy(&mut fixture, 2, 1, 0),
        ParliamentAggregateOutcomeV1::Approved
    );
    let id = fixture.state.attempt.id;
    let final_result_height = fixture
        .state
        .body(&fixture.body_id)
        .and_then(ParliamentBodyStateV1::result_height)
        .expect("completed Policy Jury result height");
    fixture
        .state
        .validate()
        .expect("the reducer's pre-certificate state is internally consistent");
    assert_eq!(
        fixture.state.validate_restored_height_v1(41),
        Err(ParliamentReducerErrorV1::IncompleteCertificate),
        "the atomic pre-certificate transient must never survive restart"
    );
    assert_eq!(
        fixture
            .state
            .construct_certificate(id, final_result_height, final_result_height),
        Err(ParliamentReducerErrorV1::InvalidCertificateHeight)
    );
    assert_eq!(
        fixture
            .state
            .construct_certificate(id, final_result_height + 1, 60),
        Err(ParliamentReducerErrorV1::InvalidCertificateHeight),
        "certification cannot be delayed beyond the final body result height"
    );
    let certificate = fixture
        .state
        .construct_certificate(id, final_result_height, 60)
        .expect("complete certificate");
    assert_eq!(certificate.body_bindings.len(), 1);
    assert_eq!(
        fixture
            .state
            .validate_restored_height_v1(final_result_height - 1),
        Err(ParliamentReducerErrorV1::InvalidCertificateHeight)
    );
    fixture
        .state
        .validate_restored_height_v1(59)
        .expect("a certified effect remains future before its due height");
    assert_eq!(
        fixture.state.validate_restored_height_v1(60),
        Err(ParliamentReducerErrorV1::WrongEnactmentHeight)
    );
    assert_eq!(
        fixture.state.mark_enacted(id, 59),
        Err(ParliamentReducerErrorV1::WrongEnactmentHeight)
    );

    let mut late = fixture.state.clone();
    assert_eq!(
        late.mark_enacted(id, 61),
        Err(ParliamentReducerErrorV1::WrongEnactmentHeight)
    );

    let mut enacted = fixture.state.clone();
    enacted.mark_enacted(id, 60).expect("enact due certificate");
    assert_eq!(
        enacted.validate_restored_height_v1(59),
        Err(ParliamentReducerErrorV1::InvalidCertificateHeight)
    );
    enacted
        .validate_restored_height_v1(60)
        .expect("terminal outcome is committed at the restored boundary");
    assert_eq!(enacted.attempt.status, GovernanceAttemptStatusV1::Enacted);
    assert_eq!(enacted.terminal_height(), Some(60));
    enacted
        .validate()
        .expect("enacted terminal state validates");
    assert!(matches!(
        enacted.mark_enacted(id, 61),
        Err(ParliamentReducerErrorV1::InvalidLifecycleTransition(_))
    ));

    let mut superseded = fixture.state.clone();
    assert_eq!(
        superseded.mark_superseded(id, 60, certificate.expected_head),
        Err(ParliamentReducerErrorV1::ExpectedHeadUnchanged)
    );
    assert_eq!(
        superseded.mark_superseded(
            id,
            60,
            GovernanceExpectedHeadV1::Absent(GovernanceExpectedHeadAbsentV1 {
                subject_id: root(99),
            }),
        ),
        Err(ParliamentReducerErrorV1::InvalidSupersedingHead),
        "another subject cannot supersede this certificate's compare-and-set head"
    );
    assert_eq!(
        superseded.mark_superseded(
            id,
            60,
            GovernanceExpectedHeadV1::Present(
                iroha_data_model::governance::types::GovernanceExpectedHeadPresentV1 {
                    subject_id: expected_head_subject(certificate.expected_head),
                    version: 0,
                    head_root: root(99),
                },
            ),
        ),
        Err(ParliamentReducerErrorV1::InvalidSupersedingHead),
        "a present superseding head must name a nonzero version"
    );
    superseded
        .mark_superseded(
            id,
            60,
            GovernanceExpectedHeadV1::Present(
                iroha_data_model::governance::types::GovernanceExpectedHeadPresentV1 {
                    subject_id: expected_head_subject(certificate.expected_head),
                    version: 1,
                    head_root: root(99),
                },
            ),
        )
        .expect("different head supersedes");
    assert_eq!(
        superseded.attempt.status,
        GovernanceAttemptStatusV1::Superseded
    );
    assert_eq!(superseded.terminal_height(), Some(60));
    assert_ne!(
        superseded.superseding_head(),
        Some(certificate.expected_head)
    );
    superseded
        .validate()
        .expect("superseded terminal state validates");
    let mut substituted_subject = superseded.clone();
    substituted_subject.superseding_head = Some(GovernanceExpectedHeadV1::Absent(
        GovernanceExpectedHeadAbsentV1 {
            subject_id: root(99),
        },
    ));
    assert_eq!(
        substituted_subject.validate(),
        Err(ParliamentReducerErrorV1::CertificateBindingMismatch),
        "restored supersession evidence must retain the certificate subject"
    );

    let mut failed = fixture.state;
    assert_eq!(
        failed.mark_execution_failed(id, 59),
        Err(ParliamentReducerErrorV1::WrongEnactmentHeight)
    );
    let expected_failure_root = parliament_execution_failure_root_v1(&certificate, 60);
    assert_eq!(
        failed
            .mark_execution_failed(id, 60)
            .expect("exact due certificate records execution failure"),
        expected_failure_root
    );
    assert_eq!(
        failed.attempt.status,
        GovernanceAttemptStatusV1::ExecutionFailed
    );
    assert_eq!(failed.terminal_height(), Some(60));
    assert_eq!(failed.execution_failure_root(), Some(expected_failure_root));
    failed
        .validate()
        .expect("execution-failed terminal state validates");
    let encoded_failure = norito::to_bytes(&failed).expect("encode execution failure state");
    let decoded_failure = norito::decode_from_bytes::<ParliamentAttemptStateV1>(&encoded_failure)
        .expect("decode execution failure state");
    assert_eq!(decoded_failure, failed);
    decoded_failure
        .validate()
        .expect("decoded execution failure state validates");
    assert!(matches!(
        failed.mark_execution_failed(id, 60),
        Err(ParliamentReducerErrorV1::InvalidLifecycleTransition(_))
    ));

    let mut corrupted_failure = failed;
    let mut corrupted_root = expected_failure_root;
    corrupted_root[0] ^= 1;
    corrupted_failure.execution_failure_root = Some(corrupted_root);
    assert_eq!(
        corrupted_failure.validate(),
        Err(ParliamentReducerErrorV1::CertificateBindingMismatch)
    );
}

#[test]
fn persistence_rejects_future_actions_and_body_stage_skips() {
    let mut fixture = opened_policy_ballot(3, 3);
    fixture
        .state
        .validate()
        .expect("opened ballot fixture validates structurally");
    for restored_height in [9, 19, 20, 29, 31, 33, 35, 39] {
        assert_eq!(
            fixture.state.validate_restored_height_v1(restored_height),
            Err(ParliamentReducerErrorV1::FuturePersistedHeight),
            "realized lifecycle state must not come from after restored height {restored_height}"
        );
    }
    fixture
        .state
        .validate_restored_height_v1(40)
        .expect("every realized opening fixture height is committed by height 40");

    assert_eq!(
        finalize_policy(&mut fixture, 2, 1, 0),
        ParliamentAggregateOutcomeV1::Approved
    );
    assert_eq!(
        fixture.state.validate_restored_height_v1(39),
        Err(ParliamentReducerErrorV1::FuturePersistedHeight),
        "the body result was not realized until height 40"
    );
    assert_eq!(
        fixture.state.validate_restored_height_v1(40),
        Err(ParliamentReducerErrorV1::IncompleteCertificate),
        "Certification is an in-transaction transient until Core constructs the certificate"
    );

    let mut skipped = fixture.state.clone();
    skipped.attempt.stage = GovernanceStageV1::PolicyJury;
    assert_eq!(
        skipped.validate(),
        Err(ParliamentReducerErrorV1::IncompleteCertificate),
        "a current-body stage cannot retain that body's completed binding"
    );
    let mut missing = fixture.state;
    missing.body_bindings.clear();
    assert_eq!(
        missing.validate(),
        Err(ParliamentReducerErrorV1::IncompleteCertificate),
        "Certification requires the exact completed required-body prefix"
    );
}

#[test]
fn parliament_pulse_slot_uses_one_canonical_json_map_key() {
    let slot = ParliamentPulseSlotV1::new(beacon_session(13), 20);
    let map = BTreeMap::from([(slot, pulse_id(14))]);
    let json = norito::json::to_json(&map).expect("encode pulse-slot map");
    assert!(json.contains(&format!("\"{}:20\"", "0d".repeat(32))));
    assert_eq!(
        norito::json::to_json_bounded(&map, json.len()).expect("exact pulse-slot map bound"),
        json
    );
    assert_eq!(
        norito::json::to_json_bounded(&map, json.len() - 1),
        Err(norito::json::BoundedJsonError::BodyTooLarge)
    );
    let decoded: BTreeMap<ParliamentPulseSlotV1, BeaconPulseId> =
        norito::json::from_json(&json).expect("decode pulse-slot map");
    assert_eq!(decoded, map);

    assert!(
        ParliamentPulseSlotV1::from_canonical_json_key(&format!("{}:20", "0D".repeat(32))).is_err(),
        "uppercase session hex must not alias the canonical map key"
    );
    assert!(
        ParliamentPulseSlotV1::from_canonical_json_key(&format!("{}:020", "0d".repeat(32)))
            .is_err(),
        "zero-padded heights must not alias the canonical map key"
    );
}

#[test]
fn parliament_pulse_slot_json_key_is_bounded_and_cancellable() {
    use norito::json::{JsonObjectKey, JsonObjectKeyOwned};

    for height in [0, 1, u64::MAX] {
        let slot = ParliamentPulseSlotV1::new(beacon_session(0xab), height);
        let key = slot.canonical_json_key();
        let limits =
            norito::core::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX);
        let (decoded, usage) = norito::core::with_decode_limits_measured(limits, || {
            ParliamentPulseSlotV1::from_json_key_text(&key)
        });
        assert_eq!(decoded.expect("fixed-size key without a heap budget"), slot);
        assert_eq!(usage.total_allocated_bytes(), 0);

        let mut streamed = String::new();
        slot.visit_json_key_text(|chunk| {
            streamed.push_str(chunk);
            Ok::<_, ()>(())
        })
        .expect("collect canonical key");
        assert_eq!(streamed, key);
        let mut calls = 0;
        assert_eq!(
            slot.visit_json_key_text(|_| {
                calls += 1;
                Err("stop")
            }),
            Err("stop")
        );
        assert_eq!(calls, 1, "stop after the first visitor error");
    }

    let session = "ab".repeat(32);
    for height in ["", "00", "+1", "-1", "1:2", " 1", "18446744073709551616"] {
        assert!(
            ParliamentPulseSlotV1::from_json_key_text(&format!("{session}:{height}")).is_err(),
            "reject noncanonical or overflowing height: {height:?}"
        );
    }
    for malformed in ["ab".repeat(31), "AB".repeat(32), "ab".repeat(4096)] {
        assert!(ParliamentPulseSlotV1::from_json_key_text(&format!("{malformed}:0")).is_err());
    }
}

#[test]
fn reducer_norito_roundtrip_is_deterministic_and_revalidated() {
    let mut fixture = opened_policy_ballot(3, 3);
    finalize_policy(&mut fixture, 2, 1, 0);
    let final_result_height = fixture
        .state
        .body(&fixture.body_id)
        .and_then(ParliamentBodyStateV1::result_height)
        .expect("completed Policy Jury result height");
    fixture
        .state
        .construct_certificate(fixture.state.attempt.id, final_result_height, 60)
        .expect("certificate");
    fixture.state.validate().expect("source state validates");
    crate::private_settlement::global_state::tests::assert_private_settlement_frame_v1(
        &fixture.state,
        "iroha_core::governance::parliament::ParliamentAttemptStateV1",
    );
    let bytes = norito::to_bytes(&fixture.state).expect("encode reducer state");
    let decoded = norito::decode_from_bytes::<ParliamentAttemptStateV1>(&bytes)
        .expect("decode reducer state");
    decoded.validate().expect("decoded state validates");
    assert_eq!(decoded, fixture.state);
    assert_eq!(
        norito::to_bytes(&decoded).expect("re-encode reducer state"),
        bytes
    );
    let json = norito::json::to_json(&decoded).expect("encode reducer state as Norito JSON");
    let json_decoded: ParliamentAttemptStateV1 =
        norito::json::from_json(&json).expect("decode reducer state from Norito JSON");
    json_decoded
        .validate()
        .expect("JSON-decoded state validates");
    assert_eq!(json_decoded, decoded);
}
